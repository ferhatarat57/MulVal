import networkx as nx

# Define the Node class
class Node:
    def __init__(self, node_id, cve_id, definition, cvss, exploitability, code_availability, defense_intensity, impact_score):
        self.node_id = node_id
        self.cve_id = cve_id
        self.definition = definition
        self.cvss = cvss
        self.exploitability = exploitability
        self.code_availability = code_availability
        self.defense_intensity = defense_intensity
        self.impact_score = impact_score  # Impact Score for risk calculation

    def __repr__(self):
        return f'Node({self.node_id}, {self.cve_id}, {self.definition}, CVSS={self.cvss}, IS={self.impact_score})'

    def calculate_atomic_attack_probability(self):
        return self.exploitability * self.code_availability * self.defense_intensity

    def calculate_node_level_risk(self):
        P_v = self.calculate_atomic_attack_probability()
        return self.cvss * self.impact_score * P_v

# Define the Graph class
class Graph:
    def __init__(self):
        self.nodes = {}
        self.edges = []
        self.graph = nx.DiGraph()

    def add_node(self, node):
        self.nodes[node.node_id] = node
        self.graph.add_node(node.node_id, **node.__dict__)

    def add_edge(self, from_node, to_node):
        self.edges.append((from_node, to_node))
        self.graph.add_edge(from_node, to_node)

    def get_node(self, node_id):
        return self.nodes[node_id]

    def get_neighbors(self, node_id):
        neighbors = [to_node for from_node, to_node in self.edges if from_node == node_id]
        neighbors += [from_node for from_node, to_node in self.edges if to_node == node_id]
        return neighbors

    def calculate_path_attack_probability(self, path):
        risk = 1
        for node_id in path:
            node = self.get_node(node_id)
            risk *= node.calculate_atomic_attack_probability()
        return round(risk, 4)

    def calculate_node_level_risk(self, node_id):
        node = self.get_node(node_id)
        return node.calculate_node_level_risk()

    def calculate_path_level_risk(self, path):
        total_risk = 0
        path_prob = self.calculate_path_attack_probability(path)
        for node_id in path:
            node = self.get_node(node_id)
            node_risk = node.calculate_node_level_risk()
            degree = len(self.get_neighbors(node_id))
            total_risk += node_risk * degree
        return total_risk * path_prob

    def calculate_graph_level_risk(self):
        total_risk = 0
        for path in nx.all_simple_paths(self.graph, source=0, target=19):
            total_risk += self.calculate_path_level_risk(path)
        return total_risk

    def find_all_paths_weighted_dfs(self, start_node, end_node, risk_threshold):
        all_paths = []

        def dfs(path, visited):
            node = path[-1]
            if node == end_node:
                path_risk = self.calculate_path_level_risk(path)
                if path_risk >= risk_threshold:
                    all_paths.append((path, path_risk))
                return

            for neighbor in self.graph.successors(node):
                if neighbor not in visited:
                    visited.add(neighbor)
                    dfs(path + [neighbor], visited)
                    visited.remove(neighbor)

        visited = set()
        visited.add(start_node)
        dfs([start_node], visited)
        return all_paths

# Create a manual attack graph with 20 nodes
def create_manual_graph():
    graph = Graph()

    # Define nodes with their properties
    nodes_info = [
        (0, 'CVE-2023-0001', 'Description of CVE-2023-0001', 7.5, 0.8, 0.9, 0.7, 8.0),
        (1, 'CVE-2023-0002', 'Description of CVE-2023-0002', 5.0, 0.6, 0.8, 0.6, 5.5),
        (2, 'CVE-2023-0003', 'Description of CVE-2023-0003', 6.0, 0.7, 0.7, 0.5, 6.2),
        (3, 'CVE-2023-0004', 'Description of CVE-2023-0004', 4.0, 0.5, 0.6, 0.8, 4.5),
        (4, 'CVE-2023-0005', 'Description of CVE-2023-0005', 8.0, 0.9, 0.8, 0.9, 7.8),
        (5, 'CVE-2023-0006', 'Description of CVE-2023-0006', 6.5, 0.7, 0.8, 0.7, 6.8),
        (6, 'CVE-2023-0007', 'Description of CVE-2023-0007', 7.0, 0.8, 0.9, 0.6, 7.5),
        (7, 'CVE-2023-0008', 'Description of CVE-2023-0008', 5.5, 0.6, 0.7, 0.8, 5.9),
        (8, 'CVE-2023-0009', 'Description of CVE-2023-0009', 6.2, 0.7, 0.8, 0.6, 6.5),
        (9, 'CVE-2023-0010', 'Description of CVE-2023-0010', 7.8, 0.8, 0.9, 0.7, 7.9),
        (10, 'CVE-2023-0011', 'Description of CVE-2023-0011', 5.0, 0.5, 0.6, 0.7, 5.2),
        (11, 'CVE-2023-0012', 'Description of CVE-2023-0012', 6.0, 0.6, 0.7, 0.8, 6.3),
        (12, 'CVE-2023-0013', 'Description of CVE-2023-0013', 4.5, 0.4, 0.6, 0.6, 4.8),
        (13, 'CVE-2023-0014', 'Description of CVE-2023-0014', 7.2, 0.7, 0.8, 0.7, 7.5),
        (14, 'CVE-2023-0015', 'Description of CVE-2023-0015', 5.8, 0.6, 0.7, 0.6, 6.0),
        (15, 'CVE-2023-0016', 'Description of CVE-2023-0016', 6.7, 0.7, 0.8, 0.7, 6.9),
        (16, 'CVE-2023-0017', 'Description of CVE-2023-0017', 7.3, 0.8, 0.9, 0.7, 7.4),
        (17, 'CVE-2023-0018', 'Description of CVE-2023-0018', 4.8, 0.5, 0.6, 0.6, 5.0),
        (18, 'CVE-2023-0019', 'Description of CVE-2023-0019', 5.7, 0.6, 0.7, 0.6, 5.9),
        (19, 'CVE-2023-0020', 'Description of CVE-2023-0020', 8.2, 0.9, 0.8, 0.8, 8.0),
    ]

    for node_info in nodes_info:
        node = Node(*node_info)
        graph.add_node(node)

    # Define edges
    edges = [
        (0, 1), (0, 2), (0, 3),
        (1, 4), (1, 5),
        (2, 6), (2, 7),
        (3, 8), (3, 9),
        (4, 10), (4, 11),
        (5, 12), (5, 13),
        (6, 14), (6, 15),
        (7, 16), (7, 17),
        (8, 18), (8, 19),
        (9, 18), (9, 19),
        (10, 14), (11, 15),
        (12, 16), (13, 17),
        (14, 18), (15, 19),
    ]

    for edge in edges:
        graph.add_edge(*edge)

    return graph

# Create the manual attack graph
manual_graph = create_manual_graph()

# Calculate graph level risk
graph_level_risk = manual_graph.calculate_graph_level_risk()
print(f'Graph Level Risk: {graph_level_risk:.4f}')

# Select source and destination nodes
src_node = 0
dest_node = 19

# Define risk threshold for path selection
risk_threshold = 3.0  # Example threshold

# Measure time for Risk-Weighted DFS-based path finding
all_paths = manual_graph.find_all_paths_weighted_dfs(src_node, dest_node, risk_threshold)

# Print paths and their risks
print(f'Number of High-Risk Paths: {len(all_paths)}')
for path, risk in all_paths:
    print(f'Path: {path}, Path Risk: {risk:.4f}')
