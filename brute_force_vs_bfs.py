import random
import networkx as nx
import time
from collections import deque
from itertools import permutations

# Define the Node class
class Node:
    def __init__(self, node_id, cve_id, definition, cvss, exploitability, code_availability, defense_intensity):
        self.node_id = node_id
        self.cve_id = cve_id
        self.definition = definition
        self.cvss = cvss
        self.exploitability = exploitability
        self.code_availability = code_availability
        self.defense_intensity = defense_intensity

    def __repr__(self):
        return f'Node({self.node_id}, {self.cve_id}, {self.definition}, CVSS={self.cvss})'

# Define the Graph class
class Graph:
    def __init__(self):
        self.nodes = {}
        self.edges = []

    def add_node(self, node):
        self.nodes[node.node_id] = node

    def add_edge(self, from_node, to_node):
        self.edges.append((from_node, to_node))

    def get_node(self, node_id):
        return self.nodes[node_id]

    def get_neighbors(self, node_id):
        neighbors = [to_node for from_node, to_node in self.edges if from_node == node_id]
        neighbors += [from_node for from_node, to_node in self.edges if to_node == node_id]
        return neighbors

    def calculate_atomic_attack_probability(self, node_id):
        node = self.get_node(node_id)
        E_i = node.exploitability
        CA_i = node.code_availability
        DI_i = node.defense_intensity
        return round(E_i * CA_i * DI_i, 4)

    def calculate_path_attack_probability(self, path):
        risk = 1
        for node_id in path:
            risk *= self.calculate_atomic_attack_probability(node_id)
        return round(risk, 4)

    def find_all_paths_bfs(self, start_node, end_node):
        graph = nx.DiGraph()
        graph.add_edges_from(self.edges)

        all_paths = []
        queue = deque([[start_node]])  # Start with a path containing only the start node

        while queue:
            path = queue.popleft()
            node = path[-1]

            if node == end_node:
                all_paths.append(path)
                continue

            for neighbor in graph.successors(node):
                if neighbor not in path:
                    new_path = list(path)
                    new_path.append(neighbor)
                    queue.append(new_path)

        return all_paths

    def is_valid_path(self, path):
        for i in range(len(path) - 1):
            if (path[i], path[i+1]) not in self.edges:
                return False
        return True

    def find_all_paths_brute_force(self, start_node, end_node):
        all_nodes = list(self.nodes.keys())
        all_paths = []

        # Generate all permutations of nodes
        for perm in permutations(all_nodes):
            if perm[0] == start_node and perm[-1] == end_node:
                if self.is_valid_path(perm):
                    all_paths.append(list(perm))

        return all_paths

def create_attack_graph(num_nodes=20):
    graph = Graph()

    for i in range(num_nodes):
        cve_id = f'CVE-{random.randint(2000, 2023)}-{random.randint(1000, 9999)}'
        definition = f'Description of {cve_id}'
        cvss = random.uniform(0.1, 10.0)

        # Randomly generate exploitability, code availability, and defense intensity values
        exploitability = random.uniform(0.1, 1.0)
        code_availability = 1 - (1 / random.uniform(1, 100)) ** 0.26
        defense_intensity = random.uniform(0.1, 1.0)

        node = Node(i, cve_id, definition, cvss, exploitability, code_availability, defense_intensity)
        graph.add_node(node)

    # Create more than num_nodes edges for multiple paths
    for _ in range(num_nodes * 3):
        from_node = random.randint(0, num_nodes - 1)
        to_node = random.randint(0, num_nodes - 1)
        if from_node != to_node:
            graph.add_edge(from_node, to_node)

    return graph

# Create a random attack graph
attack_graph = create_attack_graph()

# Print node details
for node_id, node in attack_graph.nodes.items():
    print(f'Node {node_id}: ({node.cve_id}, CVSS={node.cvss:.4f})')
    print(f'  Exploitability: {round(node.exploitability, 4)}')
    print(f'  Code Availability: {round(node.code_availability, 4)}')
    print(f'  Defense Intensity: {round(node.defense_intensity, 4)}')
    print()

# Calculate risk for the entire graph
total_risk = round(sum(attack_graph.calculate_atomic_attack_probability(node_id) for node_id in attack_graph.nodes), 4)
print(f'Total Graph Risk: {total_risk:.4f}')

# Select random source and destination nodes
src_node = random.choice(list(attack_graph.nodes.keys()))
dest_node = random.choice(list(attack_graph.nodes.keys()))

# Ensure source and destination are not the same and exist in the graph
while dest_node == src_node or dest_node not in attack_graph.nodes or src_node not in attack_graph.nodes:
    src_node = random.choice(list(attack_graph.nodes.keys()))
    dest_node = random.choice(list(attack_graph.nodes.keys()))

print(f'Source Node: {src_node}, Destination Node: {dest_node}')

# Measure time for BFS-based path finding
start_time = time.perf_counter()
bfs_paths = attack_graph.find_all_paths_bfs(src_node, dest_node)
bfs_time = time.perf_counter() - start_time
print(f'BFS Time: {bfs_time * 1000:.4f} milliseconds')  # Convert to milliseconds

# Measure time for Brute Force path finding
start_time = time.perf_counter()
brute_force_paths = attack_graph.find_all_paths_brute_force(src_node, dest_node)
brute_force_time = time.perf_counter() - start_time
print(f'Brute Force Time: {brute_force_time * 1000:.4f} milliseconds')  # Convert to milliseconds

# Print paths and counts
print(f'Number of BFS Paths: {len(bfs_paths)}')
print(f'Number of Brute Force Paths: {len(brute_force_paths)}')

print(f'\nBFS Paths: {bfs_paths}')
print(f'Brute Force Paths: {brute_force_paths}')
