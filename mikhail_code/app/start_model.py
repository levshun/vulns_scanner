from transformers import (AutoTokenizer, AutoModelForTokenClassification,
                         pipeline)
import warnings
warnings.filterwarnings('ignore')

path_to_model = "/home/mikhail/Documents/pandan_study/vkr/vulns_scanner/mikhail_code/models/nuner_as_tok_clf_190425/best_model"
final_tokenizer = AutoTokenizer.from_pretrained(path_to_model, use_fast=True, add_prefix_space=True, local_files_only=True)
final_model = AutoModelForTokenClassification.from_pretrained(path_to_model, local_files_only=True)

def run(input_string: str) -> str:
    token_classifier = pipeline(
        "token-classification", model=final_model, aggregation_strategy="first", tokenizer=final_tokenizer
    )
    res = token_classifier(input_string)
    output = ''
    for i, r in enumerate(res):
        # print('Entity: '+ r['entity_group'] + '   Word: ' + r['word'])
        output += str(f'{i+1}. ' + 'Entity: ' + r['entity_group'] + '   Word: ' + r['word'] + '   Prob: ' + str(r['score']) + '\n\t')
    # print(output)
    if output == '':
        output = 'No NER found'
    return output

if __name__ == '__main__':
    run(input())