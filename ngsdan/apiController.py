from flask import Flask, jsonify

data_store={
    1 : {"test"}
}

app = Flask(__name__)

# Define an API route
@app.route('/api/v1/getLogs', methods=['GET'])
def get_user():
     # Convert data_store to a JSON-serializable structure
    json_data_store = {
        key: [value.decode('utf-8') if isinstance(value, bytes) else value for value in values]
        for key, values in data_store.items()
    }
    return jsonify(json_data_store)



# Start the Flask app
# if __name__ == '__main__':
#     app.run(debug=False)
    



