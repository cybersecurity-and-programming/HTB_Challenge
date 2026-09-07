import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

df = pd.read_csv("uplink_spatial_auth.csv")

df["x"] = df["x"].round().astype(int)
df["y"] = df["y"].round().astype(int)

# Normalizar para que empiece en (0,0)
df["x"] -= df["x"].min()
df["y"] -= df["y"].min()

width  = df["x"].max() + 1
height = df["y"].max() + 1

qr = np.zeros((height, width), dtype=np.uint8)
mask = df["label"] == 1

for x, y in zip(df.loc[mask, "x"], df.loc[mask, "y"]):
    qr[y, x] = 1

plt.figure(figsize=(6, 6))
plt.imshow(qr, cmap="gray_r", interpolation="nearest")
plt.axis("off")
plt.title("QR reconstruido")
plt.show()