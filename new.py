import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib

data = pd.read_csv('iot23_combined.csv', sep=',')

print("Kolumny w danych:", data.columns)
print(data.head())

le_orig_h = LabelEncoder()
le_label = LabelEncoder()

data['orig_h_encoded'] = le_orig_h.fit_transform(data['id.orig_h'])
print(f"{data['orig_h_encoded']}")
data['label_encoded'] = le_label.fit_transform(data['label'])
print(f"Label {data['label_encoded']}")

X = data[['orig_h_encoded', 'duration', 'orig_bytes', 'resp_bytes', 'missed_bytes',
          'orig_pkts', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes',
          'proto_icmp', 'proto_tcp', 'proto_udp',
          'conn_state_OTH', 'conn_state_REJ', 'conn_state_RSTO', 'conn_state_RSTOS0',
          'conn_state_RSTR', 'conn_state_RSTRH', 'conn_state_S0', 'conn_state_S1',
          'conn_state_S2', 'conn_state_S3', 'conn_state_SF', 'conn_state_SH', 'conn_state_SHR']]

y = data['label_encoded']
print("Największe i najmniejsze wartości z każdej cechy:")
for column in X.columns:
    max_value = X[column].max()
    min_value = X[column].min()
    print(f"{column}: Min = {min_value}, Max = {max_value}")
    
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
print("Accuracy:", accuracy_score(y_test, y_pred))
print(classification_report(y_test, y_pred))

possible_classes = le_label.classes_
print("Wszystkie możliwe klasyfikacje (etykiety):")
for idx, class_name in enumerate(possible_classes):
    print(f"{idx}: {class_name}")

joblib.dump(model, 'random_forest_model.pkl')
joblib.dump(le_orig_h.classes_, 'le_orig_h.pkl')
joblib.dump(le_label.classes_, 'le_label.pkl')