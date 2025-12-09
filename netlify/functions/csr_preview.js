// netlify/functions/csr_preview.js
const {
  previewCsr
} = require('./certrix-core');

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type'
  };
}

exports.handler = async (event) => {
  if (event.httpMethod === 'OPTIONS') {
    return {
      statusCode: 200,
      headers: corsHeaders(),
      body: ''
    };
  }

  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      headers: { ...corsHeaders(), Allow: 'POST,OPTIONS' },
      body: 'Method not allowed'
    };
  }

  try {
    const data = JSON.parse(event.body || '{}');
    let csrBytes;
    let sourceLabel = 'pasted';

    if (data.csrBase64) {
      csrBytes = Buffer.from(data.csrBase64, 'base64');
      sourceLabel = data.csrFileName || 'file';
    } else if (data.csrText) {
      csrBytes = Buffer.from(String(data.csrText), 'utf8');
      sourceLabel = data.csrFileName ? data.csrFileName : 'pasted';
    } else {
      return {
        statusCode: 400,
        headers: {
          ...corsHeaders(),
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          error: 'CSR text or csrBase64 is required'
        })
      };
    }

    let result;
    try {
      result = previewCsr(csrBytes, sourceLabel);
    } catch (e) {
      console.error('csr_preview CSR error:', e);
      return {
        statusCode: 400,
        headers: {
          ...corsHeaders(),
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          error: String(e.message || 'Invalid CSR')
        })
      };
    }

    return {
      statusCode: 200,
      headers: {
        ...corsHeaders(),
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(result)
    };
  } catch (err) {
    console.error('csr_preview error:', err);
    return {
      statusCode: 500,
      headers: {
        ...corsHeaders(),
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ error: 'Internal server error' })
    };
  }
};
