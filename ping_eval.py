import re
import statistics
import matplotlib.pyplot as plt
from collections import Counter

# Load and extract ping times
log_file = 'ping.log'
pattern = r'Time since last ping: (\d+\.\d+) sec'
rounded_pings = []

# Extract ping times
with open(log_file, 'r') as file:
    for line in file:
        match = re.search(pattern, line)
        if match:
            ping_value = float(match.group(1))
            rounded_pings.append(round(ping_value))

# Statistics
average = statistics.mean(rounded_pings)
variance = statistics.variance(rounded_pings)
stdev = statistics.stdev(rounded_pings)

print(f"Total pings: {len(rounded_pings)}")
print(f"Average: {average:.2f} sec")
print(f"Variance: {variance:.4f}")
print(f"Standard Deviation: {stdev:.4f}")

# Count rounded ping values
ping_counts = Counter(rounded_pings)
target_groups = sorted(ping_counts.keys())
counts = [ping_counts[g] for g in target_groups]

# Plot with logarithmic y-axis
plt.figure(figsize=(6, 4))
bars = plt.bar([str(g) for g in target_groups], counts, color='mediumseagreen')
plt.yscale('log')

# Add count labels above each bar
for bar, count in zip(bars, counts):
    plt.text(bar.get_x() + bar.get_width()/2, count * 1.05, str(count),
             ha='center', va='bottom', fontsize=10)

plt.xlabel("Ping Group (Rounded on seconds)")
plt.ylabel("Frequency (Log Scale)")
plt.grid(True, which="both", axis='y', linestyle='--', alpha=0.5)
plt.tight_layout()
plt.show()
