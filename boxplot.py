import matplotlib.pyplot as plt
import numpy as np
import math

# Cost functions
def cost_type_a(T, NS): return NS * (965 + 220 * math.floor(T / 2))
def cost_type_b(T, NS): return NS * (1284 + 220 * math.floor(T / 2))

NS_values = [30, 50, 114]
time_range = np.arange(0, 60 + 1, 1)  # Time from 0 to 60 minutes, step = 1

# Collect cost values
data = []
labels = []

for NS in NS_values:
    data.append([cost_type_a(T, NS) for T in time_range])
    labels.append(f'Short (NS={NS})')
    data.append([cost_type_b(T, NS) for T in time_range])
    labels.append(f'Long (NS={NS})')

# Plot box plot
plt.figure(figsize=(10, 6))
plt.boxplot(data, labels=labels, showmeans=True)
plt.xticks(rotation=45)
plt.ylabel('Total Cost (bytes)')
plt.grid(True)
plt.tight_layout()
plt.show()
