#include "net/net_helper.h"

namespace epee
{
namespace net_utils
{
	namespace
	{
		struct new_connection
		{
			boost::promise<boost::asio::ip::tcp::socket> result_;
			boost::asio::ip::tcp::socket socket_;

			template<typename T>
			explicit new_connection(T&& executor)
			  : result_(), socket_(std::forward<T>(executor))
			{}
		};
	}

	boost::unique_future<boost::asio::ip::tcp::socket>
	direct_connect::operator()(const std::string& addr, const std::string& port, boost::asio::steady_timer& timeout) const
	{
		MDEBUG("Direct connect1");
		// Get a list of endpoints corresponding to the server name.
		//////////////////////////////////////////////////////////////////////////
		boost::asio::ip::tcp::resolver resolver(MONERO_GET_EXECUTOR(timeout));
		MDEBUG("Direct connect2");

		bool try_ipv6 = false;
		boost::asio::ip::tcp::resolver::results_type results{};
		boost::system::error_code resolve_error;

		try
		{
			results = resolver.resolve(
				boost::asio::ip::tcp::v4(), addr, port, boost::asio::ip::tcp::resolver::canonical_name, resolve_error
			);

			MDEBUG("Direct connect3");

			if (results.empty())
			{
				// if IPv4 resolution fails, try IPv6.  Unintentional outgoing IPv6 connections should only
				// be possible if for some reason a hostname was given and that hostname fails IPv4 resolution,
				// so at least for now there should not be a need for a flag "using ipv6 is ok"
				try_ipv6 = true;
			}

		}
		catch (const boost::system::system_error& e)
		{
			if (resolve_error != boost::asio::error::host_not_found &&
					resolve_error != boost::asio::error::host_not_found_try_again)
			{
				throw;
			}
			try_ipv6 = true;
		}

		if (try_ipv6)
		{
			MDEBUG("Direct connect4");
			results = resolver.resolve(
				boost::asio::ip::tcp::v6(), addr, port, boost::asio::ip::tcp::resolver::canonical_name
			);
			if (results.empty())
				throw boost::system::system_error{boost::asio::error::fault, "Failed to resolve " + addr};

			MDEBUG("Direct connect5");
		}

		//////////////////////////////////////////////////////////////////////////


		MDEBUG("Direct connect6");
		const auto shared = std::make_shared<new_connection>(MONERO_GET_EXECUTOR(timeout));
		MDEBUG("Direct connect7");
		timeout.async_wait([shared] (boost::system::error_code error)
		{
			MDEBUG("Direct connect6.2");
			if (error != boost::system::errc::operation_canceled && shared && shared->socket_.is_open())
			{
				MDEBUG("Direct connect6.3");
				shared->socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both);
				shared->socket_.close();
			}
			MDEBUG("Direct connect6.4");
		});
		MDEBUG("Direct connect8");
		shared->socket_.async_connect(*results.begin(), [shared] (boost::system::error_code error)
		{
			MDEBUG("Direct connect8.1");
			if (shared)
			{
				MDEBUG("Direct connect8.2");
				if (error)
					MDEBUG("Direct connect error");
				if (error)
					shared->result_.set_exception(boost::system::system_error{error});
				else
					shared->result_.set_value(std::move(shared->socket_));
			}
			MDEBUG("Direct connect8.3");
		});
		MDEBUG("Direct connectEND");
		return shared->result_.get_future();
	}
}
}

