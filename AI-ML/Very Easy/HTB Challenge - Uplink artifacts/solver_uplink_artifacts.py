

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

'''

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

# ============================
# 1. Cargar datos
# ============================
df = pd.read_csv("uplink_spatial_auth.csv")

# ============================
# 2. Preparar coordenadas
# ============================
# Redondear a enteros (si vienen con decimales)
df["x"] = df["x"].round().astype(int)
df["y"] = df["y"].round().astype(int)

# Normalizar para que empiece en (0,0)
df["x"] -= df["x"].min()
df["y"] -= df["y"].min()

# ============================
# 3. Crear lienzo vacío
# ============================
width  = df["x"].max() + 1
height = df["y"].max() + 1

qr = np.zeros((height, width), dtype=np.uint8)

# ============================
# 4. Pintar los módulos del QR
# ============================
# Puedes cambiar el label si el QR usa otro
mask = df["label"] == 1

for x, y in zip(df.loc[mask, "x"], df.loc[mask, "y"]):
    qr[y, x] = 1

# ============================
# 5. Mostrar QR
# ============================
plt.figure(figsize=(6, 6))
plt.imshow(qr, cmap="gray_r", interpolation="nearest")
plt.axis("off")
plt.title("QR reconstruido")
plt.show()

'''


