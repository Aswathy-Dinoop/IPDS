import numpy as np
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Conv1D, MaxPooling1D, Flatten, Dropout, BatchNormalization
from tensorflow.keras.optimizers import Adam
import matplotlib.pyplot as plt
import os

from preprocessing import load_data, preprocess_data

# Configuration
EPOCHS = 10
BATCH_SIZE = 32
MODEL_SAVE_PATH = os.path.join(os.path.dirname(__file__), 'model', 'cnn_model.h5')

def build_cnn_model(input_shape):
    """
    Builds a 1D CNN model suitable for tabular network data.
    """
    model = Sequential()
    
    # First Convolutional Layer
    model.add(Conv1D(filters=64, kernel_size=3, activation='relu', input_shape=input_shape))
    model.add(BatchNormalization())
    model.add(MaxPooling1D(pool_size=2))
    model.add(Dropout(0.2))
    
    # Second Convolutional Layer
    model.add(Conv1D(filters=128, kernel_size=3, activation='relu'))
    model.add(BatchNormalization())
    model.add(MaxPooling1D(pool_size=2))
    model.add(Dropout(0.3))
    
    # Flattening
    model.add(Flatten())
    
    # Fully Connected Layers
    model.add(Dense(128, activation='relu'))
    model.add(Dropout(0.4))
    
    model.add(Dense(64, activation='relu'))
    
    # Output Layer (Binary Classification: Normal(0) vs Attack(1))
    model.add(Dense(1, activation='sigmoid'))
    
    # Compile
    optimizer = Adam(learning_rate=0.001)
    model.compile(optimizer=optimizer, loss='binary_crossentropy', metrics=['accuracy'])
    
    return model

def train():
    print("Step 1: Loading Data...")
    # By default, tries to load KDDTrain+.txt, falls back to dummy
    df = load_data() 
    
    print("Step 2: Preprocessing Data...")
    X, y = preprocess_data(df, is_training=True)
    
    # Split training and validation
    from sklearn.model_selection import train_test_split
    X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print(f"Training data shape: {X_train.shape}")
    print(f"Validation data shape: {X_val.shape}")
    
    print("Step 3: Building Model...")
    input_shape = (X_train.shape[1], 1)
    model = build_cnn_model(input_shape)
    model.summary()
    
    print("Step 4: Training Model...")
    history = model.fit(
        X_train, y_train,
        epochs=EPOCHS,
        batch_size=BATCH_SIZE,
        validation_data=(X_val, y_val),
        verbose=1
    )
    
    print("Step 5: Saving Model...")
    if not os.path.exists(os.path.dirname(MODEL_SAVE_PATH)):
        os.makedirs(os.path.dirname(MODEL_SAVE_PATH))
    model.save(MODEL_SAVE_PATH)
    print(f"Model saved to {MODEL_SAVE_PATH}")
    
    # Step 6: Generate Accuracy Graph
    print("Step 6: Saving Accuracy Graph...")
    plt.figure(figsize=(10, 5))
    plt.plot(history.history['accuracy'], label='Train Accuracy')
    plt.plot(history.history['val_accuracy'], label='Val Accuracy')
    plt.title('CNN Model Accuracy')
    plt.xlabel('Epochs')
    plt.ylabel('Accuracy')
    plt.legend()
    plt.savefig(os.path.join(os.path.dirname(__file__), 'static', 'accuracy_graph.png'))
    print("Accuracy graph saved to static/accuracy_graph.png")

if __name__ == "__main__":
    train()
