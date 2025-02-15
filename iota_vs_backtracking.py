import random
import networkx as nx
import numpy as np
from collections import deque
from time import perf_counter
from nodes_20 import nodes_info_20, edges_20
from nodes_40 import nodes_info_40, edges_40
from nodes_60 import nodes_info_60, edges_60
from nodes_80 import nodes_info_80, edges_80


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

    def calculate_node_risk(self):
        P_v = self.calculate_atomic_attack_probability()
        return self.cvss * self.impact_score * P_v


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
        return node.calculate_node_risk()

    def calculate_path_level_risk(self, path):
        total_risk = 0
        path_prob = self.calculate_path_attack_probability(path)
        for node_id in path:
            node = self.get_node(node_id)
            node_risk = node.calculate_node_risk()
            degree = len(self.get_neighbors(node_id))
            total_risk += node_risk * degree
        return total_risk * path_prob

    def calculate_graph_level_risk(self):
        total_risk = 0
        for path in nx.all_simple_paths(self.graph, source=0, target=19):
            total_risk += self.calculate_path_level_risk(path)
        return total_risk

    # all path finding using backtracking with risk
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

    def find_all_paths_iota(self, start_node, end_node, risk_threshold):
        # IOTA algorithm to find all paths with risk calculation
        all_paths = []
        for path in nx.all_simple_paths(self.graph, source=start_node, target=end_node):
            path_risk = self.calculate_path_level_risk(path)
            if path_risk >= risk_threshold:
                all_paths.append((path, path_risk))
        return all_paths

def create_manual_graph():
    graph = Graph()

    for node_info in nodes_info_40:
        node = Node(*node_info)
        graph.add_node(node)

    for from_node, to_node in edges_40:
        graph.add_edge(from_node, to_node)

    return graph

graph = create_manual_graph()

graph_level_risk_custom = graph.calculate_graph_level_risk()

start_time = perf_counter()
custom_paths = graph.find_all_paths_weighted_dfs(0, 39, 2)  # 0.5 risk threshold
end_time = perf_counter()
custom_time = end_time - start_time

print(f"Custom method found {len(custom_paths)} paths in {custom_time:.4f} seconds")

start_time = perf_counter()
iota_paths = graph.find_all_paths_iota(0, 39, 2.5)  # last item is risk threshold
end_time = perf_counter()
iota_time = end_time - start_time

print(f"IOTA found {len(iota_paths)} paths in {iota_time:.4f} seconds")
