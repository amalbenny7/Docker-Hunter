const arrayBufferToDataURL = (arrayBuffer, mimeType) => {
  const blob = new Blob([arrayBuffer], { type: mimeType });
  return URL.createObjectURL(blob);
};

export default arrayBufferToDataURL;
