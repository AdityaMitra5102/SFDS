import base64
import json



def base64url_decode(s):
    padding = 4 - len(s) % 4
    if padding != 4:
        s += '=' * padding
    return base64.urlsafe_b64decode(s)


def base64url_encode(b):
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()

def make_presentation(presentations):
	final_presentation='~'
	pres=presentations.split('~')
	for presentation in pres:
		if not presentation:
			continue
		decoded = base64url_decode(presentation).decode()
		value = json.loads(json.loads(decoded)[1])
		path = value['path']
		choice = input(f"Do you want to disclose {path} (y/N)?")
		if choice.lower() == 'y':
			print(f'Adding {path} \n')
			final_presentation +=presentation + '~'
	return final_presentation
		
def main():
	file="disclosure.txt"
	presentations=open(file, 'r').read()
	pres=make_presentation(presentations)
	with open('presentation.txt', 'w') as f:
		f.write(pres)
	
if __name__=='__main__':
	main()