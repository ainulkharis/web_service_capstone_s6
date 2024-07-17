from flask import Flask, jsonify, Response, render_template
from ultralytics import YOLO
from ultralytics.solutions import object_counter
import cv2
from pymongo import MongoClient
import datetime
from shapely.geometry import Point

# Setup Flask app
app = Flask(__name__)

# Setup MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client.supermarket
collection = db.visitors

model = YOLO("model/best.pt")
region_of_interest = [(300, 20), (302, 680), (280, 680), (280, 20)]
counter = object_counter.ObjectCounter(view_img=True, reg_pts=region_of_interest, classes_names=model.names, draw_tracks=True)

def count_object():
    cap = cv2.VideoCapture(0)
    assert cap.isOpened()
    tracked_ids = set()
    male_count = 0
    female_count = 0
    
    while True:
        success, im0 = cap.read()
        if not success:
            break
        tracks = model.track(im0, persist=True, show=False)
        im0 = counter.start_counting(im0, tracks)
        
        # Process tracks and save to MongoDB if crossing the ROI
        if tracks[0].boxes.id is not None:
            boxes = tracks[0].boxes.xyxy.cpu()
            clss = tracks[0].boxes.cls.cpu().tolist()
            track_ids = tracks[0].boxes.id.int().cpu().tolist()

            for box, track_id, cls in zip(boxes, track_ids, clss):
                if track_id not in tracked_ids:
                    prev_position = counter.track_history[track_id][-2] if len(counter.track_history[track_id]) > 1 else None
                    current_position = (float((box[0] + box[2]) / 2), float((box[1] + box[3]) / 2))
                    
                    if len(region_of_interest) >= 3:
                        is_inside = counter.counting_region.contains(Point(current_position))
                        if prev_position and is_inside:
                            tracked_ids.add(track_id)
                            direction = "IN" if (box[0] - prev_position[0]) * (counter.counting_region.centroid.x - prev_position[0]) > 0 else "OUT"
                            
                            if cls == 0:  # Assuming class 0 is Female
                                female_count += 1
                            elif cls == 1:  # Assuming class 1 is Male
                                male_count += 1
                            
                            detection = {
                                'gender': f"Female: {female_count}, Male: {male_count}",
                                'days': datetime.datetime.now().strftime('%A'),
                                'date': datetime.datetime.now().date().isoformat(),  # Convert to string
                                'total': male_count + female_count
                            }
                            collection.insert_one(detection)

        ret, buffer = cv2.imencode('.jpg', im0)
        frame = buffer.tobytes()
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')

    cap.release()
    cv2.destroyAllWindows()

@app.route('/realtime')
def index():
    return render_template('index.html')

@app.route('/video_feed')
def video_feed():
    return Response(count_object(), mimetype='multipart/x-mixed-replace; boundary=frame')

@app.route('/data', methods=['GET'])
def get_data():
    try:
        # Mengambil semua data dari koleksi
        data = list(collection.find({}))  # Menggunakan find() tanpa argumen untuk mengambil semua data
        
        # Konversi ObjectId ke string untuk setiap dokumen
        for item in data:
            item['_id'] = str(item['_id'])
        
        return jsonify(data), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
