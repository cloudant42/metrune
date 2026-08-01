/** @type {import('next').NextConfig} */
const nextConfig = {
  output: "standalone",
  poweredByHeader: false,
  // The dashboard ships no next/image usage, and the runtime image is built
  // with --omit=optional so sharp is absent. Declaring this keeps the optimizer
  // from being reached if an <Image> is ever added without revisiting the
  // LGPL-3.0 licensing of the libvips binaries sharp would pull back in.
  images: { unoptimized: true },
};

export default nextConfig;
