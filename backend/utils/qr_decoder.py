import cv2
from pyzbar.pyzbar import decode


def decode_qr_image(image_path: str):
    try:
        img = cv2.imread(image_path)

        if img is None:
            return None

        decoded_objects = decode(img)

        if not decoded_objects:
            return None

        # Return first QR code data as string
        return decoded_objects[0].data.decode("utf-8").strip()

    except Exception as e:
        print("❌ QR decode error:", e)
        return None
