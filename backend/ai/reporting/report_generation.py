from openai import OpenAI

def generate_report(results, model="gpt-4o", temperature=0.2):
    client = OpenAI()

    prompt = f"Generate a detailed and professional penetration testing report based on the following results:\n\n{results}\n\nAlso provide remediation strategy for vulnerabilities."

    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": "You are an expert report generator."},
            {"role": "user", "content": prompt}
        ],
        temperature=temperature
    )

    return response.choices[0].message.content

if __name__ == "__main__":
    report = generate_report("just generate a dummy report for penetration testing")
    print(report)
