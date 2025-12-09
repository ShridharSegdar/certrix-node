// netlify/functions/generate.js
const {
  generateNewCertificateZip
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
    const result = await generateNewCertificateZip(data);
    if (result.error) {
      return {
        statusCode: 400,
        headers: corsHeaders(),
        body: result.error
      };
    }

    const base64 = result.buffer.toString('base64');
    return {
      statusCode: 200,
      isBase64Encoded: true,
      headers: {
        ...corsHeaders(),
        'Content-Type': 'application/zip',
        'Content-Disposition': `attachment; filename="${result.zipFilename}"`
      },
      body: base64
    };
  } catch (err) {
    console.error('generate error:', err);
    return {
      statusCode: 500,
      headers: corsHeaders(),
      body: 'Internal server error'
    };
  }
};
