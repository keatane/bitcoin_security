import numpy as np
import matplotlib.pyplot as plt
import math

def cost(T, NS):
    """Compute the total byte cost C(T) for a given time T and number of sessions NS."""
    # return NS * (965 + 220 * math.floor(T / 2))
    # return NS * (1284 + 220 * math.floor(T / 2))
    return NS * 965 + (NS - 9) * (220 * math.floor(T / 2))

# Parameters
# connection_values = [1, 5, 10, 20]  # Different NS values to compare
connection_values = [30, 50, 114]  # Different NS values to compare
time_range = np.arange(0, 60 + 1, 1)  # Time from 0 to 60 minutes, step = 1

# Plotting
plt.figure(figsize=(10, 6))

for NS in connection_values:
    costs = [cost(T, NS) for T in time_range]
    plt.step(time_range, costs, where='post', label=f'{NS} Connections')

# plt.title('Cost Over Time for Different Numbers of Connections')
plt.xlabel('Time (minutes)')
plt.ylabel('Total Cost (bytes)')
plt.yscale('log') 
plt.grid(True)
plt.legend()
plt.tight_layout()
plt.show()
