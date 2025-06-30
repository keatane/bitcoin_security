import numpy as np
import matplotlib.pyplot as plt
import math

def cost_method1(T, NS):
    """First cost calculation method."""
    return NS * 965 + (NS - 9) * (220 * math.floor(T / 2))

def cost_method2(T, NS):
    """Second cost calculation method."""
    return 200 * (NS + (NS - 9) * T)

# Parameters
connection_values = [30, 50, 114]
time_range = np.arange(0, 60 + 1, 1)

# Define fixed colors for each NS value
color_map = {
    30: 'blue',
    50: 'orange',
    114: 'green'
}

plt.figure(figsize=(10, 6))

for NS in connection_values:
    color = color_map[NS]
    costs1 = [cost_method1(T, NS) for T in time_range]
    costs2 = [cost_method2(T, NS) for T in time_range]
    
    # Method 1: solid line
    plt.step(time_range, costs1, where='post',
             label=f'Ping - {NS} Connections',
             color=color, linewidth=2)

    # Method 2: semi-transparent, thicker line
    plt.step(time_range, costs2, where='post',
             label=f'Handshake - {NS} Connections',
             color=color, linewidth=3, alpha=0.4)

plt.xlabel('Time (minutes)')
plt.ylabel('Total Cost (bytes)')
plt.title('Comparison of Cost Over Time for Two Methods')
plt.grid(True)
plt.legend()
plt.tight_layout()
plt.show()
