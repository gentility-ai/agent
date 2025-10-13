export default {
  async fetch(request, env, ctx) {

    const targetUrl = 'https://raw.githubusercontent.com/gentility-ai/agent/refs/heads/master/install.sh';

    // Fetch the content from GitHub
    const response = await fetch(targetUrl, {
      method: request.method,
      headers: request.headers,
      body: request.method !== 'GET' && request.method !== 'HEAD' ? request.body : undefined,
    });

    // Create a new response with the fetched content
    const newResponse = new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: {
        ...Object.fromEntries(response.headers),
        // CORS headers to allow access from any origin
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      }
    });

    return newResponse;
  },
};