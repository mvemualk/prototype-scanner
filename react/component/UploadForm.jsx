// UploadForm.jsx
import React, {useState} from 'react';

export default function UploadForm(){
  const [file, setFile] = useState(null);
  const [jobId, setJobId] = useState(null);

  async function upload(){
    if(!file) return;
    const fd = new FormData();
    fd.append('file', file);
    const res = await fetch('/api/upload', { method:'POST', body:fd});
    const j = await res.json();
    setJobId(j.job_id);
  }

  return (
    <div>
      <input type="file" accept=".zip" onChange={e=>setFile(e.target.files[0])}/>
      <button onClick={upload}>Upload & Scan</button>
      { jobId && <a href={`/report/${jobId}`}>View Report</a> }
    </div>
  );
}
