from flask import Flask, render_template, request, flash
from markupsafe import Markup
from start_model import run

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'

@app.route('/', methods=['GET', 'POST'])
def index():
    input_text = ''
    highlighted_text = ''
    structured_results = []
    
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

            except Exception as e:
                flash(f'Error processing text: {str(e)}')

    return render_template('index.html',
                         input_text=input_text,
                         highlighted_text=highlighted_text,
                         structured_results=structured_results)

if __name__ == '__main__':
    app.run(debug=True, port=5000)