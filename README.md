# Axum-Based Secure Messaging Server
##### By Daniel Lubliner
###### 7/6/2025
___

For this project, I used Rust with the Axum web framework and Tokio asynchronous runtime to build a server for secure messaging via WebSockets. Features include password hashing with Argon2, JWT-based authentication for protected routes, and WebSocket-based chat rooms. 

**What I'm working on now:**
- Logging user interactions.
- Modifying my Axum server to use TLS.
- Setting up a database so I can manage user permissions.
- GitHub Actions CI/CD pipeline to automatically integrate and deploy changes in the codebase.
- Refactoring my Axum handlers into a module to help clean up my `main.rs`!
___
**Directions for use**:
1. Execute `cargo build` on the command-line.
2. Execute `cargo run` to start the server. 
3. Use a tool like [Insomnia](https://insomnia.rest) to create `POST` requests on the `register` and `login` routes to receive a JWT.
4. User your JWT as a bearer token so you can access protected routes!
