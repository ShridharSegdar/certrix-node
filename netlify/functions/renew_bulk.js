// netlify/functions/renew_bulk.js
const { renewBulkZip } = require('./certrix-core');

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
    const body = JSON.parse(event.body || '{}');

    if (!body.zipBase64) {
      return {
        statusCode: 400,
        headers: corsHeaders(),
        body: 'zipBase64 is required'
      };
    }

    const zipBuffer = Buffer.from(body.zipBase64, 'base64');

    const result = await renewBulkZip(zipBuffer, body.years);

    if (result.error) {
      return {
        statusCode: 400,
        headers: corsHeaders(),
        body: result.error
      };
    }

    return {
      statusCode: 200,
      isBase64Encoded: true,
      headers: {
        ...corsHeaders(),
        'Content-Type': 'application/zip',
        'Content-Disposition': `attachment; filename="${result.filename}"`
      },
      body: result.buffer.toString('base64')
    };
  } catch (err) {
    console.error('renew_bulk error:', err);
    return {
      statusCode: 500,
      headers: corsHeaders(),
      body: 'Internal server error'
    };
  }
};
