import numpy as np
import matplotlib.pyplot as plt
import math

# Parameters
PN_values = [1000, 5000, 10000, 21966]          # Different numbers of attacker peers
NS = 30                           # Max connections per node
NX = 9                             # Legitimate connections
CB = 965                           # Cost in bytes per connection
time_range = np.arange(0, 61, 1)   # Time from 0 to 60 minutes

def cost(T, PN, NS, NX, CB):
    """Compute the total byte cost C(T) for given time T."""
    return PN * (NS * CB + (NS - NX) * (220 * math.floor(T / 2)))

# Plotting
plt.figure(figsize=(10, 6))

for PN in PN_values:
    costs = [cost(T, PN, NS, NX, CB) for T in time_range]
    plt.step(time_range, costs, where='post', label=f'PN = {PN} peers')

# plt.title('Total Byte Cost Over Time for Different Attacker Peer Counts')
plt.xlabel('Time (minutes)')
plt.ylabel('Total Cost (bytes)')
plt.grid(True)
plt.legend()
plt.tight_layout()
plt.show()
