import random

nodes_info_20 = [
    (i, f'CVE-2023-{str(i).zfill(4)}', f'Description of CVE-2023-{str(i).zfill(4)}', random.uniform(4.0, 9.0),
     random.uniform(0.4, 0.9), random.uniform(0.6, 0.9), random.uniform(0.4, 0.8), random.uniform(5.0, 9.0))
    for i in range(20)
]

edges_20 = [
    (0, 1), (0, 2), (0, 3), (1, 3), (1, 4), (2, 4), (2, 5),
    (3, 6), (3, 7), (4, 7), (4, 8), (5, 8), (5, 9), (6, 10),
    (6, 11), (7, 12), (8, 12), (8, 13), (9, 13), (9, 14),
    (10, 15), (10, 16), (11, 16), (11, 17), (12, 18), (13, 19),
    (14, 19), (15, 18), (16, 19), (17, 18), (0, 15), (1, 6),
    (2, 11), (3, 10), (4, 13), (5, 17), (6, 14), (7, 16),
    (8, 10), (9, 15), (10, 12), (11, 14), (12, 19), (13, 17),
    (14, 16), (15, 17), (16, 18), (17, 19)
]

