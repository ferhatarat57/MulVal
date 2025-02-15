import random
import networkx as nx
import math

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
        self.impact_score = random.uniform(0, 10)  # Randomly assigned IS value between 0 and 10

    def calculate_node_level_risk(self, atomic_attack_probability):
        # Node-Level Risk = CVSS Score * Impact Score (IS) * Probability (P)
        return self.cvss * self.impact_score * atomic_attack_probability

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
        return E_i * CA_i * DI_i

    def calculate_node_level_risk(self, node_id):
        atomic_attack_probability = self.calculate_atomic_attack_probability(node_id)
        node = self.get_node(node_id)
        return node.calculate_node_level_risk(atomic_attack_probability)

    def calculate_path_attack_probability(self, path):
        risk = 1
        for node_id in path:
            risk *= self.calculate_atomic_attack_probability(node_id)
        return risk

    def find_all_paths(self, start_node, end_node):
        graph = nx.DiGraph()
        graph.add_edges_from(self.edges)
        return list(nx.all_simple_paths(graph, source=start_node, target=end_node))


def create_attack_graph(num_nodes=10):
    graph = Graph()

    for i in range(num_nodes):
        cve_id = f'CVE-{random.randint(2000, 2023)}-{random.randint(1000, 9999)}'
        definition = f'Description of {cve_id}'
        cvss = random.uniform(0.1, 10.0)

        exploitability = random.uniform(0.1, 1.0)
        code_availability = 1 - (1 / random.uniform(1, 100)) ** 0.26
        defense_intensity = random.uniform(0.1, 1.0)

        node = Node(i, cve_id, definition, cvss, exploitability, code_availability, defense_intensity)
        graph.add_node(node)

    for _ in range(num_nodes * 3):
        from_node = random.randint(0, num_nodes - 1)
        to_node = random.randint(0, num_nodes - 1)
        if from_node != to_node:
            graph.add_edge(from_node, to_node)

    return graph


# Create the attack graph
attack_graph = create_attack_graph()

# Print details of each node including Node-Level Risk
for node_id, node in attack_graph.nodes.items():
    atomic_attack_probability = attack_graph.calculate_atomic_attack_probability(node_id)
    node_level_risk = attack_graph.calculate_node_level_risk(node_id)
    print(f'Node {node_id}: ({node.cve_id}, CVSS={node.cvss})')
    print(f'  Exploitability: {node.exploitability}')
    print(f'  Code Availability: {node.code_availability}')
    print(f'  Defense Intensity: {node.defense_intensity}')
    print(f'  Impact Score (IS): {node.impact_score}')
    print(f'  Atomic Attack Probability: {atomic_attack_probability}')
    print(f'  Node-Level Risk: {node_level_risk}\n')

# Calculate and print the total graph risk
total_risk = sum(attack_graph.calculate_atomic_attack_probability(node_id) for node_id in attack_graph.nodes)
print(f'Total Graph Risk: {total_risk}')

# Randomly select source and destination nodes
src_node = random.choice(list(attack_graph.nodes.keys()))
dest_node = random.choice(list(attack_graph.nodes.keys()))

while dest_node == src_node or dest_node not in attack_graph.nodes or src_node not in attack_graph.nodes:
    src_node = random.choice(list(attack_graph.nodes.keys()))
    dest_node = random.choice(list(attack_graph.nodes.keys()))

print(f'Source Node: {src_node}, Destination Node: {dest_node}')

# Find and print all paths from source to destination
all_paths = attack_graph.find_all_paths(src_node, dest_node)
print(f'All Paths from {src_node} to {dest_node}:')

path_risks = {}
for path in all_paths:
    risk = attack_graph.calculate_path_attack_probability(path)
    path_risks[tuple(path)] = risk
    print(f'Path: {path} - Risk: {risk}')

print(f'\nPath Risks: {path_risks}')
