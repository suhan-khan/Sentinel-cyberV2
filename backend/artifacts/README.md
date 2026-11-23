# Model artifacts

Place your trained scikit-learn model or Pipeline at `model.joblib`.

Also create `feature_columns.json` containing the exact ordered feature names expected by the model, for example:

```json
["feature_a", "feature_b", "feature_c"]
```

The feature list must match the model's training input. If your preprocessing is part of a scikit-learn Pipeline, save the whole Pipeline as `model.joblib`. Do not include the target/label column in `feature_columns.json`.

The API deliberately reports that inference is unavailable until these real artifacts are supplied; it does not generate fake predictions.
