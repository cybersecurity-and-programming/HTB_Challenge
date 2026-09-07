import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.cm as cm

df = pd.read_csv("uplink_spatial_auth.csv")

labels = df["label"].unique()
colors = cm.get_cmap("viridis", len(labels))

plt.figure(figsize=(6, 6))

for i, label in enumerate(labels):
    subset = df[df["label"] == 1]
    plt.scatter(
        subset["x"],
        subset["y"],
        s=120,
        color=colors(i),
        label=f"Label {label}",
        edgecolor="white",
        linewidth=0.8
    )

plt.title("Scatter plot por label")
plt.xlabel("x")
plt.ylabel("y")
plt.legend()
plt.grid(alpha=0.3)

plt.show()
