# Model Version Compatibility Report: UniGuard AI

**Project:** UniGuard AI — Detection of Cyber Threats in Unidirectional IP Traffic  
**Date:** November 3, 2026  
**Status:** Resolved & Verified  

---

## 1. Executive Summary

UniGuard AI utilizes pre-trained machine learning models and preprocessing pipelines serialized via `joblib`. Prior to this resolution, loading saved models in an environment with `scikit-learn 1.9.1` raised multiple `InconsistentVersionWarning` alerts across all core estimators (`RobustScaler`, `LabelEncoder`, `DecisionTreeClassifier`, `RandomForestClassifier`, `ExtraTreeRegressor`, `IsolationForest`, and `KMeans`).

In accordance with strict machine learning engineering standards and project constraints:
1. All pre-existing models were fully backed up prior to any modification.
2. The runtime environment dependency was aligned to `scikit-learn 1.9.0` (matching the exact serialization version of the models).
3. The dependency configuration (`requirements.txt`) was strictly pinned to `scikit-learn==1.9.0`.
4. All saved estimators and preprocessors were validated through comprehensive load tests, feature transform verifications, and multi-class threat prediction tests.
5. Zero warnings are now emitted during model loading across the entire test suite and detection pipelines.

---

## 2. Model Inventory & Training Versions

The following models reside in `models_saved/`. Analysis of their serialized metadata confirms they were trained and pickled with **scikit-learn 1.9.0**:

| Model File | Serialized Estimator / Class | Sub-Estimators Pickled | Training Version |
| :--- | :--- | :--- | :--- |
| `preprocessor.joblib` | `FlowDataPreprocessor` | `RobustScaler`, `LabelEncoder` | `1.9.0` |
| `uniguard_rf_model.joblib` | `SupervisedThreatClassifier` | `RandomForestClassifier`, `DecisionTreeClassifier` (120 trees) | `1.9.0` |
| `uniguard_xgb_model.joblib` | `SupervisedThreatClassifier` | `xgb.XGBClassifier` | `1.9.0` |
| `uniguard_isolation_forest.joblib` | `IsolationForestAnomalyDetector` | `IsolationForest`, `ExtraTreeRegressor` (100 estimators) | `1.9.0` |
| `directionality_scaler.joblib` | `sklearn.preprocessing.RobustScaler` | N/A | `1.9.0` |
| `directionality_isolation_forest.joblib` | `sklearn.ensemble.IsolationForest` | `ExtraTreeRegressor` (100 estimators) | `1.9.0` |
| `directionality_kmeans.joblib` | `sklearn.cluster.KMeans` | Lloyd Cython cluster centers (`float32`) | `1.9.0` |

---

## 3. Dependency Environment & Compatibility Analysis

The active Python environment dependencies were checked and verified for cross-compatibility:

| Package | Installed Version | Compatibility Requirements | Status |
| :--- | :--- | :--- | :--- |
| `scikit-learn` | **`1.9.0`** *(aligned from 1.9.1)* | Matches all serialized model states | **COMPATIBLE** |
| `numpy` | `2.4.3` | Meets `numpy>=1.24.1` requirement | **COMPATIBLE** |
| `scipy` | `1.17.1` | Meets `scipy>=1.10.0` requirement | **COMPATIBLE** |
| `joblib` | `1.6.0` | Meets `joblib>=1.4.0` requirement | **COMPATIBLE** |
| `xgboost` | `3.2.0` | Native scikit-learn API integration | **COMPATIBLE** |
| `shap` | `0.51.0` | TreeExplainer compatible with RF/XGBoost | **COMPATIBLE** |

### Compatibility Findings:
- **Root Cause of Warnings:** Scikit-learn's `BaseEstimator.__setstate__` compares `state.get("_sklearn_version")` against `sklearn.__version__`. When `scikit-learn 1.9.1` attempted to unpickle estimators built in `1.9.0`, it triggered `InconsistentVersionWarning`. In Cythonized estimators (such as `DecisionTreeClassifier`, `ExtraTreeRegressor`, and `KMeans`), minor version mismatches risk structural struct discrepancies or array buffer mismatches.
- **Why Warning Suppression was Rejected:** Suppressing `InconsistentVersionWarning` via warnings filters merely hides potential subtle numerical drift or memory layout issues.
- **Why Retraining was Prohibited:** The prompt explicitly forbade retraining without approval to protect benchmark reproducibility and the integrity of SIH 2026 evaluation weights.
- **Optimal Engineering Solution:** Pinning `scikit-learn==1.9.0` preserves exact bitwise reproducibility for all pre-trained weights without risking unexpected serialization side-effects.

---

## 4. Changes Made

1. **Model Backup Created**:
   - Backed up all 7 `.joblib` files and metadata JSON files from `models_saved/` into `models_saved_backup/`:
     - `models_saved_backup/directionality_isolation_forest.joblib`
     - `models_saved_backup/directionality_kmeans.joblib`
     - `models_saved_backup/directionality_scaler.joblib`
     - `models_saved_backup/preprocessor.joblib`
     - `models_saved_backup/uniguard_isolation_forest.joblib`
     - `models_saved_backup/uniguard_rf_model.joblib`
     - `models_saved_backup/uniguard_xgb_model.joblib`
     - `models_saved_backup/label_classes.json`
     - `models_saved_backup/model_metadata.json`

2. **Dependency Configuration Updated**:
   - Modified `requirements.txt` from loose range `scikit-learn>=1.3.0` to exact pin:
     ```text
     scikit-learn==1.9.0
     ```

3. **Runtime Environment Synchronized**:
   - Installed `scikit-learn==1.9.0` into the active Python 3.11 environment.

---

## 5. Validation & Test Results

### A. Environment Check
```bash
python -c "import sklearn; print(sklearn.__version__)"
# Output: 1.9.0
```

### B. Model Deserialization & Warning Audit
Every saved model file was loaded with active warning interception (`warnings.simplefilter('always')`):
- `directionality_isolation_forest.joblib`: **0 warnings**
- `directionality_kmeans.joblib`: **0 warnings**
- `directionality_scaler.joblib`: **0 warnings**
- `preprocessor.joblib`: **0 warnings**
- `uniguard_isolation_forest.joblib`: **0 warnings**
- `uniguard_rf_model.joblib`: **0 warnings**
- `uniguard_xgb_model.joblib`: **0 warnings**

### C. Feature Transformation & Prediction Verification
Tested with 50 valid multi-class flow vectors generated from the benchmark corpus:
- **Preprocessor Transform:** Output shape `(50, 24)`. Verified 5 target classes:
  `['BENIGN', 'DATA_EXFILTRATION', 'PORT_SCAN', 'SLOWLORIS', 'SYN_FLOOD']`.
- **Random Forest Classifier:**
  - Predictions shape: `(50,)`
  - Probabilities shape: `(50, 5)`
  - Classes predicted: All 5 classes active and correctly indexed.
- **XGBoost Classifier:**
  - Predictions shape: `(50,)`
  - Probabilities shape: `(50, 5)`
  - Classes predicted: All 5 classes active and correctly indexed.
- **Unsupervised Isolation Forest:**
  - Predictions shape: `(50,)` (values in `{-1, 1}`)
  - Normalized anomaly scores: shape `(50,)` (values in range `[0.428, 0.761]`).
- **Directionality Models:**
  - `RobustScaler` successfully transformed directional feature matrix.
  - `IsolationForest` decision function computed valid outlier scores.
  - `KMeans` assigned valid clusters (`[0, 1, 2, 3]`).

### D. Full Automated Test Suite
Ran `pytest tests`:
- **Result:** **29 passed** out of 29 tests (100% pass rate).
- **Warnings:** Reduced from 33 warnings down to 3 (the only remaining 3 are third-party `PendingDeprecationWarning` inside SHAP's plotting library). All `InconsistentVersionWarning` instances are completely resolved.

### E. End-to-End Pipeline Verification
Ran `python scripts/run_pcap_analysis.py`:
- Ingested: `data/samples/sample_unidirectional.pcap`
- Flows evaluated: 163 flows
- Security alerts logged: 162 alerts into `uniguard_events.db`
- `InconsistentVersionWarning` count: **0**

---

## 6. Remaining Risks & Recommendations

1. **Environment Drift in CI/CD or Fresh Installs:**
   - *Risk:* If a user or deployment script executes `pip install --upgrade scikit-learn`, the version will be bumped to >=1.9.1, reintroducing warnings.
   - *Mitigation:* `requirements.txt` has been pinned to `scikit-learn==1.9.0`. Always install using `pip install -r requirements.txt`.
2. **Third-Party SHAP Plotting Deprecation:**
   - *Risk:* SHAP 0.51.0 contains internal deprecation calls in `shap/plots/colors/_colors.py:47-49` (`Colormap.set_bad`).
   - *Mitigation:* This is cosmetic and localized strictly to SHAP plot color mapping; it has zero impact on core inference, TreeExplainer values, or risk scores.

