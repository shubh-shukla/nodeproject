import { v2 as cloudinary } from "cloudinary";
import fs from "fs";
import { ApiError } from "./APIError.js";

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const uploadToCloudinary = async (localFilePath) => {
  try {
    if (!fs.existsSync(localFilePath)) {
      return null;
    }
    const response = await cloudinary.uploader.upload(localFilePath, {
      resource_type: "auto",
    });
    fs.unlinkSync(localFilePath);
    return response;
  } catch (error) {
    fs.unlinkSync(localFilePath);
    console.log(error);
    return null;
  }
};

const deleteFromCloudinary = async (fileUrl) => {
  try {
    const publicId = getPublicIdFromUrl(fileUrl);

    if (!publicId) {
      return null;
    }

    const response = await cloudinary.uploader.destroy(publicId);
    return response;
  } catch (error) {
    console.log(error);
    return null;
  }
};

const getPublicIdFromUrl = (url) => {
  const regex = /([\w\d_-]*)\.?[^\\\/]*$/i;
  return url.match(regex)[1];
};

export { uploadToCloudinary, deleteFromCloudinary };
