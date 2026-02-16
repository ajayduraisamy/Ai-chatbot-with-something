import torch

# 🔷 Path to your best.pt
weights_path = r'C:\Users\venka\Desktop\Animal detection using yolo\yolov\yolov5-master\best.pt'

# 🔷 Load the model
model_data = torch.load(weights_path, map_location='cpu')

# 🔷 Get class names
class_names = model_data['model'].names

# 🔷 Print them
print("✅ Classes trained in this model:")
for idx, name in class_names.items():
    print(f"  {idx}: {name}")
