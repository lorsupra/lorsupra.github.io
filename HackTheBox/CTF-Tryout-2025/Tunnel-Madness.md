---
layout: default
title: Tunnel Madness - Rev
page_type: writeup
---
# HTB: Tunnel Madness – 3D Maze Pathfinding

**Category:** Reverse Engineering

## 0. Challenge Overview

This challenge provided a binary (`tunnelmadness`) containing a 3D maze represented as binary data. The goal: parse the maze structure, navigate from entrance to exit, and extract the flag character-by-character from the visited nodes.

**The setup:**
- 20×20×20 3D grid embedded in binary at offset `0x4060`
- Each node is 24 bytes: `{x, y, z, visited, up, down, left, right, forward, backward, flag_char, padding}`
- Start at (0, 0, 0), goal at (19, 19, 19)
- Only certain directions are traversable from each node
- Flag built by concatenating `flag_char` of visited nodes in path order

**Core concept:** This is a **3D maze pathfinding problem** requiring breadth-first search (BFS) to find the shortest valid path through connected nodes. The binary contains the full maze graph as a serialized data structure.

## 1. Initial Reconnaissance

I examined the binary:
```bash
file tunnelmadness
```

Output:
```
tunnelmadness: ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped
```

Checked for interesting symbols:
```bash
nm tunnelmadness | grep -i maze
```

Output:
```
0000000000004060 D maze_data
0000000000001189 T navigate_maze
```

Ran the binary:
```bash
./tunnelmadness
```

Output:
```
[*] Welcome to the Tunnel Madness!
[*] Navigate through the 3D maze to find the flag.
[*] Enter your path (sequence of moves):
> test
[!] Invalid path. Try again.
```

**Key observation:** The binary expects a specific sequence of moves through the maze. Random input is rejected.

## 2. Extracting Maze Data

I examined the data section to understand the structure:
```bash
objdump -s -j .data tunnelmadness | head -30
```

Output shows dense binary data starting at `0x4060`. Each node appears to be 24 bytes.

I calculated the expected size:
```
20 × 20 × 20 nodes = 8,000 nodes
8,000 nodes × 24 bytes = 192,000 bytes (0x2EE00)
```

I extracted the maze data:
```bash
dd if=tunnelmadness of=maze.bin bs=1 skip=$((0x4060)) count=192000
```

Output:
```
192000+0 records in
192000+0 records out
192000 bytes (192 kB, 188 KiB) copied
```

## 3. Reverse Engineering the Node Structure

I disassembled the `navigate_maze` function to understand how nodes are accessed:
```bash
objdump -M intel -d tunnelmadness | grep -A 200 "<navigate_maze>"
```

Key assembly patterns:
```assembly
navigate_maze:
    ; Load maze base address
    lea    rax, [rip+0x4060]  ; maze_data
    
    ; Calculate node offset: (z*400 + y*20 + x) * 24
    imul   r8, r10, 400       ; z * 20 * 20
    imul   r9, r11, 20        ; y * 20
    add    r8, r9
    add    r8, r12            ; + x
    imul   r8, 24             ; * sizeof(node)
    
    ; Access node fields
    mov    al, [rax+r8+0]     ; x coordinate
    mov    al, [rax+r8+1]     ; y coordinate
    mov    al, [rax+r8+2]     ; z coordinate
    mov    al, [rax+r8+3]     ; visited flag
    mov    al, [rax+r8+4]     ; up connection
    mov    al, [rax+r8+5]     ; down connection
    mov    al, [rax+r8+6]     ; left connection
    mov    al, [rax+r8+7]     ; right connection
    mov    al, [rax+r8+8]     ; forward connection
    mov    al, [rax+r8+9]     ; backward connection
    mov    al, [rax+r8+10]    ; flag character
```

**Reconstructed C structure:**
```c
typedef struct {
    uint8_t x;          // 0: X coordinate (0-19)
    uint8_t y;          // 1: Y coordinate (0-19)
    uint8_t z;          // 2: Z coordinate (0-19)
    uint8_t visited;    // 3: Visited flag
    uint8_t up;         // 4: Can move up (+Y)?
    uint8_t down;       // 5: Can move down (-Y)?
    uint8_t left;       // 6: Can move left (-X)?
    uint8_t right;      // 7: Can move right (+X)?
    uint8_t forward;    // 8: Can move forward (+Z)?
    uint8_t backward;   // 9: Can move backward (-Z)?
    uint8_t flag_char;  // 10: Character for this node
    uint8_t padding[13]; // 11-23: Unused
} MazeNode;

MazeNode maze[20][20][20];  // 8000 nodes total
```

## 4. Parsing the Maze Structure

I wrote a parser to load the maze into memory:
```python
#!/usr/bin/env python3
"""
Parse the 3D maze structure from binary data
"""
import struct
from pathlib import Path

MAZE_SIZE = 20
NODE_SIZE = 24

class MazeNode:
    def __init__(self, data):
        # Unpack the 24-byte node structure
        fields = struct.unpack('11B13x', data)
        
        self.x = fields[0]
        self.y = fields[1]
        self.z = fields[2]
        self.visited = fields[3]
        self.up = fields[4]
        self.down = fields[5]
        self.left = fields[6]
        self.right = fields[7]
        self.forward = fields[8]
        self.backward = fields[9]
        self.flag_char = chr(fields[10]) if 32 <= fields[10] < 127 else '?'
    
    def get_connections(self):
        """Return list of valid moves from this node"""
        moves = []
        if self.up:       moves.append(('up', 0, 1, 0))
        if self.down:     moves.append(('down', 0, -1, 0))
        if self.left:     moves.append(('left', -1, 0, 0))
        if self.right:    moves.append(('right', 1, 0, 0))
        if self.forward:  moves.append(('forward', 0, 0, 1))
        if self.backward: moves.append(('backward', 0, 0, -1))
        return moves
    
    def __repr__(self):
        return f"Node({self.x},{self.y},{self.z}) '{self.flag_char}'"

def load_maze(filename):
    """Load maze from binary file"""
    data = Path(filename).read_bytes()
    
    maze = {}
    offset = 0
    
    for z in range(MAZE_SIZE):
        for y in range(MAZE_SIZE):
            for x in range(MAZE_SIZE):
                node_data = data[offset:offset+NODE_SIZE]
                node = MazeNode(node_data)
                
                # Verify coordinates match expected position
                assert node.x == x and node.y == y and node.z == z, \
                    f"Coordinate mismatch at ({x},{y},{z})"
                
                maze[(x, y, z)] = node
                offset += NODE_SIZE
    
    return maze

# Load the maze
maze = load_maze('maze.bin')
print(f"[+] Loaded {len(maze)} nodes")

# Examine start node
start = maze[(0, 0, 0)]
print(f"[+] Start node: {start}")
print(f"    Available moves: {[m[0] for m in start.get_connections()]}")

# Examine goal node
goal = maze[(19, 19, 19)]
print(f"[+] Goal node: {goal}")
```

Running the parser:
```bash
python3 parse_maze.py
```

Output:
```
[+] Loaded 8000 nodes
[+] Start node: Node(0,0,0) 'H'
    Available moves: ['right', 'forward']
[+] Goal node: Node(19,19,19) '}'
```

**Key observation:** Start node contains 'H' (beginning of HTB flag format), goal node contains '}' (end of flag). The flag is distributed across the path.

## 5. Implementing BFS Pathfinding

I implemented breadth-first search to find the shortest path:
```python
#!/usr/bin/env python3
"""
Solve the 3D maze using BFS and extract the flag
"""
from collections import deque
from parse_maze import load_maze

def bfs_solve(maze, start, goal):
    """
    Find shortest path through maze using BFS
    Returns: list of nodes in path order
    """
    queue = deque([(start, [start])])
    visited = {start}
    
    while queue:
        current, path = queue.popleft()
        
        # Check if we reached the goal
        if current == goal:
            return path
        
        # Get current node
        node = maze[current]
        
        # Try all valid moves
        for move_name, dx, dy, dz in node.get_connections():
            next_pos = (current[0] + dx, current[1] + dy, current[2] + dz)
            
            # Check bounds
            if not all(0 <= c < 20 for c in next_pos):
                continue
            
            # Check if already visited
            if next_pos in visited:
                continue
            
            # Mark as visited and add to queue
            visited.add(next_pos)
            queue.append((next_pos, path + [next_pos]))
    
    return None  # No path found

# Load maze
print("[*] Loading maze...")
maze = load_maze('maze.bin')

# Solve
print("[*] Solving maze with BFS...")
start_pos = (0, 0, 0)
goal_pos = (19, 19, 19)

path = bfs_solve(maze, start_pos, goal_pos)

if path is None:
    print("[!] No path found!")
    exit(1)

print(f"[+] Found path with {len(path)} nodes")

# Extract flag
print("[*] Extracting flag from path...")
flag_chars = []
for pos in path:
    node = maze[pos]
    flag_chars.append(node.flag_char)
    print(f"  {pos} -> '{node.flag_char}'")

flag = ''.join(flag_chars)
print(f"\n[+] FLAG: {flag}")
```

Running the solver:
```bash
python3 solve_maze.py
```

Output:
```
[*] Loading maze...
[+] Loaded 8000 nodes
[*] Solving maze with BFS...
[+] Found path with 58 nodes
[*] Extracting flag from path...
  (0, 0, 0) -> 'H'
  (1, 0, 0) -> 'T'
  (2, 0, 0) -> 'B'
  (3, 0, 0) -> '{'
  (3, 1, 0) -> 'n'
  (3, 2, 0) -> '4'
  (3, 3, 0) -> 'v'
  (3, 3, 1) -> '1'
  (3, 3, 2) -> 'g'
  (3, 3, 3) -> '4'
  (4, 3, 3) -> 't'
  (5, 3, 3) -> '1'
  (6, 3, 3) -> 'n'
  (7, 3, 3) -> 'g'
  (7, 4, 3) -> '_'
  (7, 5, 3) -> 't'
  (7, 6, 3) -> 'h'
  (7, 7, 3) -> 'r'
  (7, 7, 4) -> '0'
  (7, 7, 5) -> 'u'
  (7, 7, 6) -> 'g'
  (7, 7, 7) -> 'h'
  (8, 7, 7) -> '_'
  (9, 7, 7) -> 't'
  (10, 7, 7) -> 'h'
  (11, 7, 7) -> '3'
  (11, 8, 7) -> '_'
  (11, 9, 7) -> 't'
  (11, 10, 7) -> 'u'
  (11, 11, 7) -> 'n'
  (11, 11, 8) -> 'n'
  (11, 11, 9) -> '3'
  (11, 11, 10) -> 'l'
  (11, 11, 11) -> '5'
  (12, 11, 11) -> '_'
  (13, 11, 11) -> '1'
  (14, 11, 11) -> 'n'
  (15, 11, 11) -> '_'
  (15, 12, 11) -> '3'
  (15, 13, 11) -> 'D'
  (15, 13, 12) -> '_'
  (15, 13, 13) -> 'm'
  (15, 13, 14) -> '4'
  (15, 13, 15) -> 'z'
  (16, 13, 15) -> '3'
  (17, 13, 15) -> '_'
  (18, 13, 15) -> 'g'
  (19, 13, 15) -> 'r'
  (19, 14, 15) -> '4'
  (19, 15, 15) -> 'p'
  (19, 16, 15) -> 'h'
  (19, 17, 15) -> '5'
  (19, 17, 16) -> '_'
  (19, 17, 17) -> 'f'
  (19, 17, 18) -> 't'
  (19, 17, 19) -> 'w'
  (19, 18, 19) -> '!'
  (19, 19, 19) -> '}'

[+] FLAG: HTB{n4v1g4t1ng_thr0ugh_th3_tunn3l5_1n_3D_m4z3_gr4ph5_ftw!}
```

✔ **Success:** Flag extracted by following the BFS path through the 3D maze.

## 6. Visualization Script

To better understand the maze structure, I created a visualization:
```python
#!/usr/bin/env python3
"""
Visualize the maze solution path
"""
from parse_maze import load_maze
from solve_maze import bfs_solve
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D

# Load and solve
maze = load_maze('maze.bin')
path = bfs_solve(maze, (0, 0, 0), (19, 19, 19))

# Extract coordinates
xs = [pos[0] for pos in path]
ys = [pos[1] for pos in path]
zs = [pos[2] for pos in path]

# Create 3D plot
fig = plt.figure(figsize=(12, 10))
ax = fig.add_subplot(111, projection='3d')

# Plot path
ax.plot(xs, ys, zs, 'b-', linewidth=2, label='Solution Path')

# Mark start and end
ax.scatter([0], [0], [0], c='green', s=200, marker='o', label='Start')
ax.scatter([19], [19], [19], c='red', s=200, marker='*', label='Goal')

# Labels
ax.set_xlabel('X')
ax.set_ylabel('Y')
ax.set_zlabel('Z')
ax.set_title(f'3D Maze Solution Path ({len(path)} nodes)')
ax.legend()

plt.savefig('maze_solution.png', dpi=150)
print("[+] Saved visualization to maze_solution.png")
```

## 7. Why This Works – Understanding 3D Graph Traversal

### Graph Representation

The maze is a **directed graph** where:
- **Vertices** = 8,000 nodes (positions in 3D space)
- **Edges** = directional connections (up/down/left/right/forward/backward)

**Not all edges are bidirectional:**
```
Node(5,5,5) might have:
  - right: YES (can move to 6,5,5)
  - left: NO (cannot move to 4,5,5)

Node(6,5,5) might have:
  - left: YES (can move to 5,5,5)
  
So: 5,5,5 → 6,5,5 is valid
But: 6,5,5 → 5,5,5 might also be valid (separate edge)
```

This creates an **asymmetric adjacency relationship**.

### Why BFS Works

**Breadth-First Search** guarantees finding the shortest path in an unweighted graph:

```python
def bfs(start, goal):
    queue = [start]
    visited = {start}
    
    while queue:
        current = queue.pop(0)  # FIFO: shortest path first
        
        if current == goal:
            return "found!"
        
        for neighbor in current.neighbors:
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append(neighbor)
```

**Properties:**
- **Completeness**: If a path exists, BFS finds it
- **Optimality**: First path found is shortest (for unweighted graphs)
- **Time complexity**: O(V + E) where V=vertices, E=edges
- **Space complexity**: O(V) for visited set and queue

### Why DFS Would Fail

**Depth-First Search** goes deep first:
```python
def dfs(current, goal, visited):
    if current == goal:
        return "found!"
    
    for neighbor in current.neighbors:
        if neighbor not in visited:
            visited.add(neighbor)
            dfs(neighbor, goal, visited)  # Go deep immediately
```

**Problems:**
- May find a valid path, but not the shortest
- Can get stuck in deep branches before exploring short paths
- No guarantee of finding optimal solution

### Alternative: Dijkstra's Algorithm

If nodes had different costs:
```python
import heapq

def dijkstra(start, goal):
    pq = [(0, start)]  # (cost, node)
    costs = {start: 0}
    
    while pq:
        current_cost, current = heapq.heappop(pq)
        
        if current == goal:
            return current_cost
        
        for neighbor, edge_cost in current.neighbors:
            new_cost = current_cost + edge_cost
            
            if neighbor not in costs or new_cost < costs[neighbor]:
                costs[neighbor] = new_cost
                heapq.heappush(pq, (new_cost, neighbor))
```

**When to use:**
- Edge weights differ (e.g., some tunnels are longer)
- Need guaranteed shortest path by distance/cost
- Graph has varying edge costs

### Real-World Applications

**Navigation Systems:**
```python
# Google Maps uses variants of Dijkstra/A*
shortest_path = dijkstra(
    start="Home",
    goal="Work",
    weights=lambda road: road.distance + road.traffic_delay
)
```

**Network Routing:**
```python
# BGP finds paths through internet routers
best_route = shortest_path(
    start=source_router,
    goal=destination_router,
    metric=lambda link: link.latency + link.cost
)
```

**Game AI:**
```python
# NPCs pathfind through game world
path = a_star(
    start=enemy.position,
    goal=player.position,
    heuristic=euclidean_distance
)
```

**Maze Solving Robots:**
```python
# Robot navigation using flood fill
def flood_fill(maze):
    # BFS from goal backwards
    distances = bfs(goal, all_cells)
    
    # Robot follows decreasing distances
    while current != goal:
        current = min(neighbors, key=lambda n: distances[n])
```

## 8. Defensive Considerations

### Why Embed Mazes in Binaries?

**Obfuscation technique:**
- Hide control flow in complex data structures
- Make static analysis harder
- Increase reverse engineering effort

**License validation:**
```c
// Maze-based key check
bool validate_key(char *key) {
    // Key is valid iff it spells path through maze
    for (int i = 0; i < strlen(key); i++) {
        if (!can_move(current, key[i])) {
            return false;
        }
        current = next_node(current, key[i]);
    }
    return current == goal;
}
```

**Anti-tampering:**
```c
// Code integrity check hidden in maze traversal
uint32_t checksum = 0;
for (each node in path) {
    checksum ^= *((uint32_t*)(&code_section + node.offset));
}
return checksum == expected;
```

### Extracting Data from Binaries

**Tools used in this challenge:**
```bash
# Extract raw data
dd if=binary of=data.bin bs=1 skip=OFFSET count=SIZE

# Parse structures
xxd data.bin | less

# Automate with Python
struct.unpack(format, binary_data)
```

**Defense: Encrypt embedded data**
```c
// XOR maze with key derived from machine ID
void decrypt_maze() {
    uint32_t key = get_machine_id();
    for (int i = 0; i < MAZE_SIZE; i++) {
        maze[i] ^= key;
    }
}
```

**Defense: Distribute data**
```c
// Maze nodes spread throughout binary
MazeNode* get_node(int x, int y, int z) {
    // Compute address using non-linear function
    void *addr = base + hash(x, y, z);
    return decrypt_node(addr);
}
```

### Preventing Static Extraction

**Code obfuscation:**
```c
// Instead of linear array
MazeNode maze[8000];

// Use computed addresses
#define NODE(x,y,z) (*(MazeNode*)(base + hash(x) + hash(y) + hash(z)))
```

**Runtime generation:**
```c
// Generate maze at runtime using deterministic seed
void init_maze() {
    srand(0x12345678);
    for (int i = 0; i < MAZE_SIZE; i++) {
        maze[i] = generate_node(rand());
    }
}
```

**Virtual machine:**
```c
// Interpret maze operations through VM
void vm_navigate(uint8_t *bytecode) {
    while (*bytecode != OP_EXIT) {
        switch (*bytecode++) {
            case OP_MOVE_UP: current.y++; break;
            case OP_CHECK_FLAG: verify_char(); break;
            // ...
        }
    }
}
```

## 9. Summary

By parsing a 3D maze structure embedded in a binary and applying breadth-first search, I reconstructed the flag from the optimal path:

1. **Identified maze location** - 8,000 nodes × 24 bytes at offset `0x4060`
2. **Reverse engineered node structure** - Analyzed assembly to determine field layout
3. **Extracted binary data** - Used `dd` to dump 192KB maze blob
4. **Parsed maze graph** - Built Python representation of 20×20×20 grid
5. **Implemented BFS** - Found shortest path from (0,0,0) to (19,19,19)
6. **Extracted flag** - Concatenated `flag_char` from each node in path order
7. **Recovered flag** - `HTB{n4v1g4t1ng_thr0ugh_th3_tunn3l5_1n_3D_m4z3_gr4ph5_ftw!}`

The challenge demonstrated **graph traversal in 3D space**, requiring understanding of:
- Binary data structure parsing
- Directed graph representation
- BFS pathfinding algorithm
- Coordinate system transformations

This technique mirrors real-world scenarios:
- **Game map analysis** - Extracting level geometry from game files
- **Network topology** - Mapping router connections for optimal routing
- **Code flow analysis** - Understanding program control flow through CFG
- **Hardware layouts** - Routing traces on PCBs

The key lesson: **complex data structures in binaries are still extractable**. Whether it's a maze, encryption key table, or validation logic, if it's in the binary, it can be dumped and analyzed. Obfuscation through complexity only raises the bar—determined reverse engineers will still succeed.

**Flag:** `HTB{n4v1g4t1ng_thr0ugh_th3_tunn3l5_1n_3D_m4z3_gr4ph5_ftw!}`
