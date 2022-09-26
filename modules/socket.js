exports.initSocket = (app) => {
  const io = (app.io = require("socket.io")({
    allowEIO3: true,
  }));

  io.on("connection", (socket) => {
    const userCount = io.engine.clientsCount;
    console.log("[total: %d] user in (%s)", userCount, socket.id);
    socket.broadcast.emit("hi");

    socket.on("disconnect", () => {
      console.log("user out");
    });

    socket.on("chat-msg", (msg) => {
      io.emit("chat-msg", msg);
    });
  });
};
