//node decrypt_chromemininer.js
(async () => {
    const s = "_NOT_THE_SECRET_";
    
    const v = await crypto.subtle.importKey(
        "raw", 
        new TextEncoder().encode(s), 
        { name: "AES-CBC" }, 
        true, 
        ["decrypt"]
    );

    const hexString = "E242E64261D21969F65BEDF954900A995209099FB6C3C682C0D9C4B275B1C212BC188E0882B6BE72C749211241187FA8";
    const p = Buffer.from(hexString, 'hex');

    try {
        const d = await crypto.subtle.decrypt(
            { name: "AES-CBC", iv: new TextEncoder().encode(s) }, 
            v, 
            p
        );
        console.log(new TextDecoder().decode(d));
    } catch (err) {
        console.error("Error al desencriptar: Revisa que la clave ('s') o el IV tengan la longitud correcta para AES.", err.message);
    }
})();
