from flask import Flask, request, jsonify
from flask_cors import CORS
import skylos
import json
import os
import webbrowser
from threading import Timer
from skylos.constants import DEFAULT_EXCLUDE_FOLDERS

app = Flask(__name__)
CORS(app)


@app.route("/")
def serve_frontend():
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Skylos Dead Code Analyzer</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Helvetica Neue', sans-serif;
            background: #000000;
            color: #ffffff;
            min-height: 100vh;
            padding: 20px;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
        }

        .header {
            text-align: center;
            margin-bottom: 40px;
        }

        .header h1 {
            font-size: 3rem;
            margin-bottom: 10px;
            color: #ffffff;
            font-weight: 300;
            letter-spacing: -1px;
        }

        .header p {
            color: #888888;
            font-size: 1.1rem;
            margin-top: 10px;
            font-weight: 400;
        }

        .controls {
            background: #111111;
            border: 1px solid #333333;
            border-radius: 12px;
            padding: 32px;
            margin-bottom: 32px;
        }

        .folder-input {
            margin-bottom: 25px;
        }

        .folder-input label {
            display: block;
            font-weight: bold;
            margin-bottom: 10px;
            color: #ffffff;
        }

        .folder-input input {
            width: 100%;
            padding: 16px;
            background: #222222;
            color: #ffffff;
            border: 1px solid #444444;
            border-radius: 8px;
            font-family: inherit;
            font-size: 14px;
            transition: border-color 0.2s ease;
        }

        .folder-input input:focus {
            outline: none;
            border-color: #ffffff;
        }

        .folder-input input::placeholder {
            color: #888888;
        }

        .analyze-btn {
            background: #ffffff;
            color: #000000;
            border: none;
            padding: 16px 32px;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 500;
            font-family: inherit;
            font-size: 14px;
            margin-right: 15px;
            transition: all 0.2s ease;
        }

        .analyze-btn:hover {
            background: #f0f0f0;
            transform: translateY(-1px);
        }

        .analyze-btn:disabled {
            background: #666666;
            color: #ffffff;
            cursor: not-allowed;
            transform: none;
        }

        .confidence-control {
            margin-top: 25px;
        }

        .confidence-control label {
            display: block;
            font-weight: bold;
            margin-bottom: 10px;
            color: #ffffff;
        }

        .confidence-slider {
            width: 100%;
            height: 6px;
            background: #333333;
            outline: none;
            border-radius: 3px;
            -webkit-appearance: none;
        }

        .confidence-slider::-webkit-slider-thumb {
            -webkit-appearance: none;
            appearance: none;
            width: 20px;
            height: 20px;
            border-radius: 50%;
            background: #ffffff;
            cursor: pointer;
        }

        .confidence-slider::-moz-range-thumb {
            width: 20px;
            height: 20px;
            border-radius: 50%;
            background: #ffffff;
            cursor: pointer;
            border: none;
        }

        .summary {
            background: #111111;
            border: 1px solid #333333;
            border-radius: 8px;
            padding: 25px;
            margin-bottom: 30px;
        }

        .summary h2 {
            margin-bottom: 20px;
            color: #ffffff;
        }

        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
        }

        .summary-item {
            background: #222222;
            border: 1px solid #444444;
            border-radius: 4px;
            padding: 15px;
            text-align: center;
        }

        .summary-item .count {
            font-size: 2rem;
            font-weight: bold;
            color: #ffffff;
            margin-bottom: 5px;
        }

        .summary-item .label {
            color: #cccccc;
            text-transform: uppercase;
            font-size: 0.9rem;
        }

        .results {
            background: #111111;
            border: 1px solid #333333;
            border-radius: 8px;
            padding: 25px;
        }

        .results h2 {
            margin-bottom: 20px;
            color: #ffffff;
        }

        .dead-code-list {
            max-height: 600px;
            overflow-y: auto;
        }

        .dead-code-item {
            background: #222222;
            border: 1px solid #444444;
            border-radius: 4px;
            padding: 15px;
            margin-bottom: 10px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .item-details {
            flex-grow: 1;
        }

        .item-name {
            font-weight: bold;
            color: #ffffff;
            margin-bottom: 5px;
        }

        .item-location {
            color: #999999;
            font-size: 0.9rem;
        }

        .item-meta {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .item-type {
            background: #ffffff;
            color: #000000;
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 0.8rem;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .item-confidence {
            color: #ffffff;
            font-weight: bold;
        }

        .no-results {
            text-align: center;
            padding: 40px;
            color: #666666;
        }

        .loading {
            text-align: center;
            padding: 40px;
            color: #ffffff;
        }

        .error {
            background: #330000;
            border: 1px solid #660000;
            color: #ff6666;
            padding: 15px;
            border-radius: 4px;
            margin-bottom: 20px;
        }

        ::-webkit-scrollbar {
            width: 8px;
        }

        ::-webkit-scrollbar-track {
            background: #222222;
        }

        ::-webkit-scrollbar-thumb {
            background: #444444;
            border-radius: 4px;
        }

        ::-webkit-scrollbar-thumb:hover {
            background: #666666;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Skylos Dead Code Analyzer</h1>
            <p>Find and eliminate unused code in your Python projects</p>
        </div>

        <div class="controls">
            <div class="folder-input">
                <label for="folderPath">Project Path:</label>
                <input type="text" id="folderPath" placeholder="/path/to/your/python/project" value="./">
            </div>
            
            <button class="analyze-btn" id="analyzeBtn">Analyze Project</button>
            
            <div class="confidence-control">
                <label for="confidenceSlider">Confidence Threshold: <span id="confidenceValue">60</span>%</label>
                <input type="range" id="confidenceSlider" class="confidence-slider" 
                       min="0" max="100" value="60" step="1">
            </div>
        </div>

        <div id="errorMessage"></div>

        <div class="summary">
            <h2>Summary</h2>
            <div class="summary-grid">
                <div class="summary-item">
                    <div class="count" id="functionsCount">0</div>
                    <div class="label">Unreachable Functions</div>
                </div>
                <div class="summary-item">
                    <div class="count" id="importsCount">0</div>
                    <div class="label">Unused Imports</div>
                </div>
                <div class="summary-item">
                    <div class="count" id="parametersCount">0</div>
                    <div class="label">Unused Parameters</div>
                </div>
                <div class="summary-item">
                    <div class="count" id="variablesCount">0</div>
                    <div class="label">Unused Variables</div>
                </div>
                <div class="summary-item">
                    <div class="count" id="classesCount">0</div>
                    <div class="label">Unused Classes</div>
                </div>
            </div>
        </div>

        <div class="results">
            <h2>Dead Code Items</h2>
            <div class="dead-code-list" id="deadCodeList">
                <div class="no-results">
                    <p>Enter a project path and click "Analyze Project" to scan for dead code.</p>
                </div>
            </div>
        </div>
    </div>

    <script>
        let analysisData = null;
        let confidenceThreshold = 60;

        const slider = document.getElementById('confidenceSlider');
        const confidenceValue = document.getElementById('confidenceValue');
        const analyzeBtn = document.getElementById('analyzeBtn');
        const folderPath = document.getElementById('folderPath');
        const errorMessage = document.getElementById('errorMessage');

        slider.addEventListener('input', (e) => {
            confidenceThreshold = parseInt(e.target.value);
            confidenceValue.textContent = confidenceThreshold;
            if (analysisData) {
                updateDisplay();
            }
        });

        analyzeBtn.addEventListener('click', analyzeProject);

        function showError(message) {
            errorMessage.innerHTML = `<div class="error">${message}</div>`;
        }

        function clearError() {
            errorMessage.innerHTML = '';
        }

        async function analyzeProject() {
            const path = folderPath.value.trim();
            if (!path) {
                showError('Please enter a project path');
                return;
            }

            clearError();
            analyzeBtn.textContent = 'Analyzing...';
            analyzeBtn.disabled = true;

            document.getElementById('deadCodeList').innerHTML = '<div class="loading">Analyzing project...</div>';

            try {
                const response = await fetch('/api/analyze', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        path: path,
                        confidence: confidenceThreshold
                    })
                });

                if (!response.ok) {
                    const errorData = await response.json();
                    throw new Error(errorData.error || `Analysis failed: ${response.statusText}`);
                }

                const result = await response.json();
                analysisData = result;
                updateDisplay();

            } catch (error) {
                showError(`Error: ${error.message}`);
                document.getElementById('deadCodeList').innerHTML = '<div class="no-results"><p>Analysis failed. Check the error message above.</p></div>';
            }

            analyzeBtn.textContent = 'Analyze Project';
            analyzeBtn.disabled = false;
        }

        function updateDisplay() {
            if (!analysisData) return;

            const filteredData = getFilteredData();
            updateSummary(filteredData);
            updateDeadCodeList(filteredData);
        }

        function getFilteredData() {
            const data = {
                functions: analysisData.unused_functions || [],
                imports: analysisData.unused_imports || [],
                parameters: analysisData.unused_parameters || [],
                variables: analysisData.unused_variables || [],
                classes: analysisData.unused_classes || []
            };

            Object.keys(data).forEach(key => {
                data[key] = data[key].filter(item => item.confidence >= confidenceThreshold);
            });

            return data;
        }

        function updateSummary(data) {
            document.getElementById('functionsCount').textContent = data.functions.length;
            document.getElementById('importsCount').textContent = data.imports.length;
            document.getElementById('parametersCount').textContent = data.parameters.length;
            document.getElementById('variablesCount').textContent = data.variables.length;
            document.getElementById('classesCount').textContent = data.classes.length;
        }

        function updateDeadCodeList(data) {
            const listElement = document.getElementById('deadCodeList');
            const allItems = [];

            Object.keys(data).forEach(category => {
                data[category].forEach(item => {
                    allItems.push({
                        ...item,
                        category: category.slice(0, -1)
                    });
                });
            });

            if (allItems.length === 0) {
                listElement.innerHTML = `
                    <div class="no-results">
                        <p>No dead code found at confidence level ${confidenceThreshold}%</p>
                    </div>
                `;
                return;
            }

            allItems.sort((a, b) => b.confidence - a.confidence);

            listElement.innerHTML = allItems.map(item => `
                <div class="dead-code-item">
                    <div class="item-details">
                        <div class="item-name">${item.name}</div>
                        <div class="item-location">${item.file}:${item.line}</div>
                    </div>
                    <div class="item-meta">
                        <span class="item-type">${item.category}</span>
                        <span class="item-confidence">${item.confidence}%</span>
                    </div>
                </div>
            `).join('');
        }
    </script>
</body>
</html>"""


@app.route("/api/analyze", methods=["POST"])
def analyze_project():
    try:
        data = request.json
        path = data.get("path")
        confidence = data.get("confidence", 60)

        if not path:
            return jsonify({"error": "Path is required"}), 400

        if not os.path.exists(path):
            return jsonify({"error": f"Path does not exist: {path}"}), 400

        exclude_folders = app.config.get("EXCLUDE_FOLDERS", DEFAULT_EXCLUDE_FOLDERS)

        result_json = skylos.analyze(
            path, conf=confidence, exclude_folders=exclude_folders
        )
        result = json.loads(result_json)

        return jsonify(result)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


def start_server(exclude_folders=None):
    if exclude_folders is None:
        exclude_folders = DEFAULT_EXCLUDE_FOLDERS
    app.config["EXCLUDE_FOLDERS"] = exclude_folders

    def open_browser():
        webbrowser.open("http://localhost:5090")

    print(" Starting Skylos Web Interface...")
    print("Opening browser at: http://localhost:5090")

    Timer(1.5, open_browser).start()

    app.run(debug=False, host="0.0.0.0", port=5090, use_reloader=False)


if __name__ == "__main__":
    start_server()
