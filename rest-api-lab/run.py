from app import app

if __name__ == "__main__":
    # Running the app with debug=True enables auto-reloading 
    # and provides a debugger in the browser if errors occur.
    app.run(debug=True, port=5000)