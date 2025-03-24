from dotenv import load_dotenv
import os
from openai import OpenAI

class OpenAIClient:
    def __init__(self):
        # Load environment variables
        load_dotenv()
        self.client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    
    def create_completion(self, messages):
        """
        Create a text completion using OpenAI API.

        Args:
        messages (list): A list of dictionaries defining the interaction history,
                         where each dictionary contains 'role' and 'content'.

        Returns:
        str: The content of the response message.
        """
        completion = self.client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=messages
        )
        return completion.choices[0].message.content.strip()

def get_answer(client, system, prompt):
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": prompt}
    ]
    response = client.create_completion(messages)
    return response

# Usage
if __name__ == "__main__":
    client = OpenAIClient()
    messages = [
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": "Hello!"}
    ]
    response = client.create_completion(messages)
    print(response)
