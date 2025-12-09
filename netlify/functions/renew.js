// netlify/functions/renew.js
const {
  renewFromCsrBytes
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

    if (data.csrBase64) {
      csrBytes = Buffer.from(data.csrBase64, 'base64');
    } else if (data.csrText) {
      csrBytes = Buffer.from(String(data.csrText), 'utf8');
    } else {
      return {
        statusCode: 400,
        headers: corsHeaders(),
        body: 'CSR text or csrBase64 is required'
      };
    }

    let result;
    try {
      result = await renewFromCsrBytes(
        csrBytes,
        data.years,
        data.csrFileName || 'certificate'
      );
    } catch (e) {
      console.error('renew CSR error:', e);
      return {
        statusCode: 400,
        headers: corsHeaders(),
        body: String(e.message || 'Invalid CSR')
      };
    }

    const base64 = result.buffer.toString('base64');

    return {
      statusCode: 200,
      isBase64Encoded: true,
      headers: {
        ...corsHeaders(),
        'Content-Type': 'application/x-pem-file',
        'Content-Disposition': `attachment; filename="${result.filename}"`,
        'X-Suggested-Filename': result.filename
      },
      body: base64
    };
  } catch (err) {
    console.error('renew error:', err);
    return {
      statusCode: 500,
      headers: corsHeaders(),
      body: 'Internal server error'
    };
  }
};
