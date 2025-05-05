import mediapipe as mp
import cv2

def detect_face(image_path):
    mp_face_detection = mp.solutions.face_detection
    mp_drawing = mp.solutions.drawing_utils
    
    image = cv2.imread(image_path)
    with mp_face_detection.FaceDetection(min_detection_confidence=0.2) as face_detection:
        results = face_detection.process(cv2.cvtColor(image, cv2.COLOR_BGR2RGB))
        
        if results.detections:
            for detection in results.detections:
                mp_drawing.draw_detection(image, detection)
                
            return image
        else:
            return "No face detected."


# Initialize MediaPipe Hands solution
mp_hands = mp.solutions.hands
mp_drawing = mp.solutions.drawing_utils

def detect_hand_gesture(image_path):
    """
    Detects hand(s) in an image and returns the image with hand landmarks drawn,
    or a message if no hands are detected.
    
    Args:
        image_path (str): The path to the image file.
        
    Returns:
        image (ndarray) if hands detected, else str message.
    """
    image = cv2.imread(image_path)
    if image is None:
        return "Image not found."

    with mp_hands.Hands(
        static_image_mode=True,
        max_num_hands=2,  # Detect up to 2 hands
        min_detection_confidence=0.5
    ) as hands:
        # Convert image to RGB as MediaPipe uses RGB format
        image_rgb = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
        results = hands.process(image_rgb)

        if results.multi_hand_landmarks:
            for hand_landmarks in results.multi_hand_landmarks:
                # Draw landmarks on the original BGR image
                mp_drawing.draw_landmarks(
                    image, hand_landmarks, mp_hands.HAND_CONNECTIONS)
            return image
        else:
            return "No hand detected."