from database import get_latest_model_metrics
metrics = get_latest_model_metrics()
print('Current metrics:')
for m in metrics:
    print(f'{m["model_name"]}: F1={m["f1_score"]:.4f}, Acc={m["accuracy"]:.4f}')