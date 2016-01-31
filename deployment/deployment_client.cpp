#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <fstream>
#include <streambuf>
#include <boost/asio.hpp>

using boost::asio::ip::tcp;

enum {
	max_length = 10240
};
/**
 * @brief The main function of the deployment client.
 */
int main(int argc, char* argv[]) {
	try {
		/**Check if client was executed with 3 arguments.
		 */
		if (argc != 3) {
			std::cerr << "Usage: ./client <host> <filename>\n";
			return 1;
		}

		/**Prepare and open connection to the deployment server at port 9999.
		 */
		boost::asio::io_service io_service;
		tcp::resolver resolver(io_service);
		tcp::resolver::query query(tcp::v4(), argv[1], "9999");
		tcp::resolver::iterator iterator = resolver.resolve(query);
		tcp::socket s(io_service);
		boost::asio::connect(s, iterator);

		/**Send the file.
		 */
		char request[max_length];
		std::ifstream t(argv[2]);
		std::stringstream buffer;
		buffer << t.rdbuf();
		strcpy(request, buffer.str().c_str());
		size_t request_length = strlen(request);
		boost::asio::write(s, boost::asio::buffer(request, request_length));
		std::cout << "Sent deployment request to host " << argv[1] << ".\n";
	} catch (std::exception& e) {
		std::cerr << "Exception: " << e.what() << "\n";
	}

	return 0;
}
