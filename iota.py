import networkx as nx
import random
import matplotlib.pyplot as plt

# IOTA benzeri bir DAG yapısı oluşturmak için gerekli sınıf
class IOTADAG:
    def __init__(self):
        self.graph = nx.DiGraph()  # Yönlendirilmiş Döngüsüz Çizge (DAG)

    def add_node(self, node_id):
        self.graph.add_node(node_id)

    def add_edge(self, from_node, to_node):
        self.graph.add_edge(from_node, to_node)

    def simulate_tangle(self, num_transactions):
        # İlk iki düğümü başlat
        for i in range(2):
            self.add_node(i)

        # Daha sonra gelen her düğüm, önceki iki düğümü onaylar
        for i in range(2, num_transactions):
            self.add_node(i)
            approved_nodes = random.sample(list(self.graph.nodes()), k=3)  # Daha fazla düğüm onaylayarak karmaşıklığı artırıyoruz
            for node in approved_nodes:
                self.add_edge(i, node)

        # Ek olarak, son düğüme giden yolları oluşturmayı deneyin
        for i in range(num_transactions - 1):
            if random.random() > 0.3:  # Çizgeyi daha karmaşık hale getirmek için rastgele kenarlar ekleyin
                self.add_edge(i, num_transactions - 1)

    def draw_graph(self):
        pos = nx.spring_layout(self.graph)
        nx.draw(self.graph, pos, with_labels=True, node_color='lightblue', node_size=500, font_size=10, font_weight='bold')
        plt.show()

    def find_attack_paths(self, start_node, end_node):
        # Başlangıç ve bitiş düğümleri arasındaki tüm yolları bulun
        paths = list(nx.all_simple_paths(self.graph, source=start_node, target=end_node))
        return paths

# Saldırı çizgesinin simülasyonu için sınıf
class AttackGraph:
    def __init__(self):
        self.iota_dag = IOTADAG()

    def create_attack_scenario(self, num_transactions):
        self.iota_dag.simulate_tangle(num_transactions)

    def visualize_attack_graph(self):
        self.iota_dag.draw_graph()

    def analyze_attack_paths(self, start_node, end_node):
        paths = self.iota_dag.find_attack_paths(start_node, end_node)
        if paths:
            print(f"Possible attack paths from Node {start_node} to Node {end_node}:")
            for idx, path in enumerate(paths, 1):
                print(f"Path {idx}: " + " -> ".join(map(str, path)))
            print(f"\nTotal number of attack paths: {len(paths)}")
        else:
            print(f"No paths found from Node {start_node} to Node {end_node}.")

# Saldırı çizgesini oluştur ve analiz et
attack_graph = AttackGraph()
num_transactions = 20  # Düğüm sayısını artırarak daha fazla yol bulma şansını artırıyoruz
attack_graph.create_attack_scenario(num_transactions)
attack_graph.visualize_attack_graph()

# Saldırı yollarını analiz et
start_node = 0  # Başlangıç düğümü
end_node = num_transactions - 1  # Bitiş düğümü
attack_graph.analyze_attack_paths(start_node, end_node)
