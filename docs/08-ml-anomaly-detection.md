# Advanced - Supervised Route Classification

The current Python monitor uses deterministic route-policy checks as the primary detection
mechanism. If `scikit-learn` and `numpy` are available, it also trains a small Random Forest
classifier from synthetic lab data and uses that model as a secondary signal.

This should be described accurately as supervised route-classification using synthetic
training data. It is not unsupervised anomaly detection.

## Why Rules Stay Primary

BGP security controls should be explainable. The rules in `monitor/detect.py` directly check:

- Whether a route overlaps the protected prefix `192.168.100.0/24`.
- Whether an announcement is a more-specific route inside protected space.
- Whether the origin AS is authorized.
- Whether suspicious ASNs appear in the transit part of the AS path.
- Whether AS_PATH is missing for a protected route.

These checks are deterministic and testable. The ML model can add a useful lab signal, but it
does not replace route policy.

## Feature Vector

The optional classifier uses three numeric features:

| Feature | Description |
|---------|-------------|
| `Path_Length` | Number of ASNs in the AS path |
| `Prefix_Length` | Prefix length, such as `24` or `25` |
| `Origin_ASN` | Last ASN in AS_PATH |

The model is trained at process startup with deterministic seeds:

```python
random.seed(42)
np.random.seed(42)
RandomForestClassifier(n_estimators=15, random_state=42)
```

## Runtime Behavior

If the optional ML dependencies are installed, the monitor logs that the classifier is
trained. If they are unavailable, the monitor continues using deterministic checks only.

The classifier can only cause a route to be treated as suspicious after the route has passed
the explicit rule checks. This keeps the lab understandable and avoids making ML the only
defense.

## Testing

The unit tests focus on the rule-based behavior and logging helpers:

```bash
python -m pytest tests -v
```

Future ML-specific tests should validate feature extraction and deterministic model output,
but should not make the lab dependent on heavyweight packages for basic correctness tests.
