import numpy as np
import matplotlib.pyplot as plt
import math

def cost_type_long(T, NS):
    """Cost Model B: Higher base cost."""
    return NS * (1284 + 220 * math.floor(T / 2))

def cost_type_heavy(T, NS):
    """Cost Model C: Heavier per-interval cost."""
    return NS * (965 + 593 * math.floor(T / 2))

# Parameters
connection_values = [30, 50, 114]  # Different NS values to compare
time_range = np.arange(0, 60 + 1, 1)  # Time from 0 to 60 minutes

colors = {
    30: 'tab:blue',
    50: 'tab:green',
    114: 'tab:orange'
}

plt.figure(figsize=(10, 6))

for NS in connection_values:
    costs_b = [cost_type_long(T, NS) for T in time_range]
    plt.step(time_range, costs_b, where='post',
             label=f'{NS} Connections - Long (optimized)', color=colors[NS], linestyle='--')

    costs_c = [cost_type_heavy(T, NS) for T in time_range]
    plt.step(time_range, costs_c, where='post',
             label=f'{NS} Connections - Long', color=colors[NS], linestyle='-')

plt.xlabel('Time (minutes)')
plt.ylabel('Total Cost (bytes)')
plt.grid(True)
plt.legend()
plt.tight_layout()
plt.show()
