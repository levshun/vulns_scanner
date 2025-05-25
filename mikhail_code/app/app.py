from flask import Flask, render_template, request, flash
from markupsafe import Markup
from start_model import run
from test import pipeline

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'

@app.route('/', methods=['GET', 'POST'])
def index():
    input_text = ''
    highlighted_text = ''
    structured_results = []
    suggestions = []
    versions = []
    
    if request.method == 'POST':
        input_text = request.form['text']
        if not input_text.strip():
            flash('Please enter some text to analyze.')
        else:
            try:
                # Get NER results from your model
                entities = run(input_text)
                
                # Create highlighted text
                text_html = input_text
                # Process entities in reverse order to maintain correct positions
                for entity in sorted(entities, key=lambda x: x['start'], reverse=True):
                    start = entity['start']
                    end = entity['end']
                    entity_class = entity['entity_group'].lower()
                    word = input_text[start:end]
                    # Wrap the word in a span with appropriate class
                    text_html = text_html[:start] + \
                               f'<span class="highlight {entity_class}">{word}</span>' + \
                               text_html[end:]
                
                highlighted_text = Markup(text_html)  # Mark as safe HTML
                
                # Prepare structured results
                structured_results = [{
                    'type': entity['entity_group'],
                    'value': entity['word'],
                    'score': entity['score']
                } for entity in entities]
                result = pipeline(input_text)
                print(result['suggestions'])
                suggestions = []
                for x in result['suggestions']:
                    suggestions.append(':'.join(x.split()))
                # print(suggestions)
                versions = result.get('versions', [])
                
                if versions:
                    versions = [str(v).strip("'[]") for v in result['versions']]
                


            except Exception as e:
                flash(f'Error processing text: {str(e)}')

    return render_template('index.html',
                         input_text=input_text,
                         highlighted_text=highlighted_text,
                         structured_results=structured_results,
                         suggestions = suggestions,
                         versions = versions)

@app.route('/download', methods=['POST'])
def download_csv():
    suggestions = request.form.getlist('suggestions')
    versions = request.form.getlist('versions')
    
    # Create CSV content
    csv_data = "Vendor\tProduct\tVersion\tCPE\n"
    for sugg in suggestions:
        for version in versions:
            csv_data += f"{sugg}\t{version}\t{sugg+':'+version}\n"
    
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=suggestions_test.csv"}
    )

if __name__ == '__main__':
    app.run(debug=True, port=5000)