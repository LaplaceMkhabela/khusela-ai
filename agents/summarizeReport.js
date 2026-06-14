require('dotenv').config();
const Groq = require('groq-sdk');

const groq = new Groq({
  apiKey: process.env.GROQ_API_KEY
});

async function summarizeReport(rawReport) {
  try {
    const reportText =
      typeof rawReport === 'string'
        ? rawReport
        : JSON.stringify(rawReport, null, 2);

    console.log('🤖 Generating AI summary with Groq...');

    const completion = await groq.chat.completions.create({
      model: 'llama-3.1-8b-instant',
      temperature: 0.3,
      max_tokens: 1024,
      messages: [
        {
          role: 'system',
          content: 'You are a security expert. Analyze dependency vulnerability reports and provide concise, actionable Markdown summaries. Focus on critical issues first, then provide remediation steps.'
        },
        {
          role: 'user',
          content: `Here is the dependency vulnerability report. Please provide a clear summary highlighting the most critical issues and suggested actions:\n\n${reportText}`
        }
      ]
    });

    console.log('✅ AI summary generated');

    return (
      completion.choices?.[0]?.message?.content ??
      'Unable to generate AI summary at this time.'
    );
  } catch (err) {
    console.error('Groq error:', err);
    return 'AI summary service is temporarily unavailable. Please review the raw report data.';
  }
}

module.exports = summarizeReport;