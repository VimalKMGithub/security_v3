package org.vimal.security.v3.utils;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.qrcode.QRCodeWriter;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public final class QrUtility {
    private QrUtility() {
    }

    private static final int DEFAULT_SIZE = 300;
    private static final String DEFAULT_IMAGE_FORMAT = "PNG";

    public static byte[] generateQRCode(String content) throws IOException, WriterException {
        return generateQRCode(content, DEFAULT_SIZE, DEFAULT_IMAGE_FORMAT);
    }

    private static byte[] generateQRCode(String content, int size, String format) throws WriterException, IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        MatrixToImageWriter.writeToStream(new QRCodeWriter().encode(content, BarcodeFormat.QR_CODE, size, size), format, outputStream);
        return outputStream.toByteArray();
    }
}
