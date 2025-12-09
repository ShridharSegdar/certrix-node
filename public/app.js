// public/app.js

const form = document.getElementById('cert-form');
const output = document.getElementById('output');
const errorBox = document.getElementById('error');
const submitBtn = document.getElementById('submit-btn');

const privateKeyTextarea = document.getElementById('privateKey');
const certificateTextarea = document.getElementById('certificate');
const downloadKeyBtn = document.getElementById('download-key');
const downloadCertBtn = document.getElementById('download-cert');

let lastCommonName = 'certificate';
let lastPrivateKey = '';
let lastCertificate = '';

function downloadTextFile(filename, text) {
  const blob = new Blob([text], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  errorBox.style.display = 'none';
  output.style.display = 'none';

  submitBtn.disabled = true;
  submitBtn.textContent = 'Generating...';

  const formData = new FormData(form);
  const payload = Object.fromEntries(formData.entries());

  lastCommonName = payload.commonName || 'certificate';

  try {
    const res = await fetch('/.netlify/functions/generate-cert', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    const data = await res.json();

    if (!res.ok) {
      throw new Error(data.error || 'Failed to generate certificate');
    }

    lastPrivateKey = data.privateKey;
    lastCertificate = data.certificate;

    privateKeyTextarea.value = data.privateKey;
    certificateTextarea.value = data.certificate;

    output.style.display = 'block';
  } catch (err) {
    console.error(err);
    errorBox.textContent = err.message || 'Something went wrong';
    errorBox.style.display = 'block';
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = 'Generate Certificate';
  }
});

downloadKeyBtn.addEventListener('click', () => {
  if (!lastPrivateKey) return;
  downloadTextFile(`${lastCommonName}.key`, lastPrivateKey);
});

downloadCertBtn.addEventListener('click', () => {
  if (!lastCertificate) return;
  downloadTextFile(`${lastCommonName}.crt`, lastCertificate);
});
